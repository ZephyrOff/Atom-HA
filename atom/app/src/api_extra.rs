//! API : historique, versions, sauvegarde, conflits, maintenance, jetons d'API, test de résolution.

use crate::api::{bad, Actor, ApiErr, Res};
use crate::dnswire;
use crate::model;
use crate::snapshots;
use crate::state::{self, App};
use crate::store::now_ms;
use axum::extract::{Path, Query as QS, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/history", get(history))
        .route("/api/history/revert", post(history_revert))
        .route("/api/versions", get(versions).post(version_create))
        .route("/api/versions/{id}", delete(version_delete))
        .route("/api/versions/{id}/diff", get(version_diff))
        .route("/api/versions/{id}/restore", post(version_restore))
        .route("/api/backup", get(backup_download))
        .route("/api/backup/restore", post(backup_restore))
        .route("/api/conflicts", get(conflicts))
        .route("/api/conflicts/clear", post(conflicts_clear))
        .route("/api/conflicts/{cid}/resolve", post(conflict_resolve))
        .route("/api/conflicts/{cid}/restore-loser", post(conflict_restore_loser))
        .route("/api/maintenance", get(maintenance))
        .route("/api/maintenance/compact", post(maintenance_compact))
        .route("/api/tokens", get(tokens_list).post(token_create))
        .route("/api/tokens/{id}", delete(token_delete).put(token_update))
        .route("/api/resolve", post(resolve_test))
}

fn node_names(app: &App) -> Value {
    let mut m = serde_json::Map::new();
    m.insert(app.node_id(), json!(app.node_name()));
    for (id, st) in app.peer_status.lock().iter() {
        m.insert(id.clone(), json!(st.name));
    }
    Value::Object(m)
}

// ---------- historique ----------

#[derive(Deserialize, Default)]
struct HistParams {
    limit: Option<usize>,
    col: Option<String>,
    search: Option<String>,
}

async fn history(State(app): State<Arc<App>>, QS(p): QS<HistParams>) -> Res {
    let items = app.store.history(p.limit.unwrap_or(200).clamp(1, 1000), &p.col.unwrap_or_default(), &p.search.unwrap_or_default());
    Ok(Json(json!({"entries": items, "node_names": node_names(&app)})))
}

#[derive(Deserialize)]
struct RevertReq {
    ts: u64,
    col: String,
    id: String,
}

async fn history_revert(State(app): State<Arc<App>>, Extension(actor): Extension<Actor>, Json(r): Json<RevertReq>) -> Res {
    if !model::COLLECTIONS.contains(&r.col.as_str()) {
        return Err(bad("collection inconnue"));
    }
    let e = app.store.history_entry(r.ts, &r.col, &r.id).ok_or_else(|| bad("entrée d'historique introuvable"))?;
    match (&e.before, &e.action[..]) {
        (None, "create") => app.store.delete_as(&r.col, &r.id, &actor.0),
        (Some(before), _) => {
            let v = model::validate(&r.col, before.clone()).map_err(bad)?;
            app.store.put_as(&r.col, &r.id, v, &actor.0);
        }
        _ => return Err(bad("cette modification ne peut pas être annulée (valeur trop volumineuse ou absente)")),
    }
    Ok(Json(json!({"ok": true})))
}

// ---------- versions ----------

async fn versions(State(app): State<Arc<App>>) -> Res {
    Ok(Json(json!({"versions": snapshots::list(&app), "current_objects": app.store.export().len()})))
}

#[derive(Deserialize, Default)]
struct VersionReq {
    label: Option<String>,
}

async fn version_create(State(app): State<Arc<App>>, Json(r): Json<VersionReq>) -> Res {
    let label = r.label.unwrap_or_default();
    let label = if label.trim().is_empty() { "Version manuelle".to_string() } else { label.trim().chars().take(80).collect() };
    let a = app.clone();
    let m = tokio::task::spawn_blocking(move || snapshots::take(&a, &label, false)).await.map_err(|e| bad(e.to_string()))?;
    Ok(Json(json!({"version": m})))
}

async fn version_delete(State(app): State<Arc<App>>, Path(id): Path<String>) -> Res {
    if snapshots::delete(&app, &id) {
        Ok(Json(json!({"ok": true})))
    } else {
        Err(ApiErr(StatusCode::NOT_FOUND, "version introuvable".into()))
    }
}

async fn version_diff(State(app): State<Arc<App>>, Path(id): Path<String>) -> Res {
    let objs = snapshots::load(&app, &id).ok_or_else(|| ApiErr(StatusCode::NOT_FOUND, "version introuvable".into()))?;
    Ok(Json(json!({"changes": snapshots::diff(&app, &objs)})))
}

async fn version_restore(State(app): State<Arc<App>>, Extension(actor): Extension<Actor>, Path(id): Path<String>) -> Res {
    let objs = snapshots::load(&app, &id).ok_or_else(|| ApiErr(StatusCode::NOT_FOUND, "version introuvable".into()))?;
    let a = app.clone();
    let _ = tokio::task::spawn_blocking(move || snapshots::take(&a, "Avant restauration", true)).await;
    let (put, del) = app.store.restore(&objs, true, &format!("{} (restauration)", actor.0));
    Ok(Json(json!({"ok": true, "written": put, "deleted": del})))
}

// ---------- sauvegarde ----------

/// Date et heure UTC « AAAAMMJJ-HHMM » (algorithme de calendrier grégorien).
fn stamp(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}-{:02}{:02}", rem / 3600, rem % 3600 / 60)
}

async fn backup_download(State(app): State<Arc<App>>) -> Response {
    let objs: Vec<Value> = app.store.export().into_iter().map(|(c, i, v)| json!({"col": c, "id": i, "val": v})).collect();
    let body = json!({
        "format": "atom-backup",
        "version": 1,
        "created_at": now_ms(),
        "node": app.node_name(),
        "atom_version": state::VERSION,
        "objects": objs,
    });
    let name = format!("atom-sauvegarde-{}.json", stamp(now_ms()));
    (
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
        ],
        serde_json::to_vec_pretty(&body).unwrap_or_default(),
    )
        .into_response()
}

#[derive(Deserialize)]
struct RestoreReq {
    backup: Value,
    /// replace (défaut) : la configuration devient celle de la sauvegarde ; merge : on ajoute et met à jour.
    mode: Option<String>,
}

async fn backup_restore(State(app): State<Arc<App>>, Extension(actor): Extension<Actor>, Json(r): Json<RestoreReq>) -> Res {
    if r.backup.get("format").and_then(|v| v.as_str()) != Some("atom-backup") {
        return Err(bad("ce fichier n'est pas une sauvegarde Atom"));
    }
    let list = r.backup.get("objects").and_then(|v| v.as_array()).ok_or_else(|| bad("sauvegarde sans objets"))?;
    let mut objs: Vec<(String, String, Value)> = Vec::new();
    let mut ignored = 0;
    for o in list {
        let col = o.get("col").and_then(|v| v.as_str()).unwrap_or("");
        let id = o.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let val = o.get("val").cloned().unwrap_or(Value::Null);
        if !model::COLLECTIONS.contains(&col) || id.is_empty() {
            ignored += 1;
            continue;
        }
        // Tout est validé avant d'écrire quoi que ce soit.
        let v = model::validate(col, val).map_err(|e| bad(format!("objet {col}/{id} invalide : {e}")))?;
        objs.push((col.to_string(), id.to_string(), v));
    }
    let replace = r.mode.as_deref() != Some("merge");
    let a = app.clone();
    let _ = tokio::task::spawn_blocking(move || snapshots::take(&a, "Avant restauration d'une sauvegarde", true)).await;
    let (put, del) = app.store.restore(&objs, replace, &format!("{} (restauration)", actor.0));
    Ok(Json(json!({"ok": true, "written": put, "deleted": del, "ignored": ignored})))
}

// ---------- conflits ----------

async fn conflicts(State(app): State<Arc<App>>) -> Res {
    Ok(Json(json!({"conflicts": app.store.conflicts(), "node_names": node_names(&app)})))
}

async fn conflict_resolve(State(app): State<Arc<App>>, Path(cid): Path<String>) -> Res {
    app.store.resolve_conflict(&cid).ok_or_else(|| ApiErr(StatusCode::NOT_FOUND, "conflit introuvable".into()))?;
    Ok(Json(json!({"ok": true})))
}

async fn conflict_restore_loser(State(app): State<Arc<App>>, Extension(actor): Extension<Actor>, Path(cid): Path<String>) -> Res {
    let c = app
        .store
        .conflicts()
        .into_iter()
        .find(|c| c.cid == cid)
        .ok_or_else(|| ApiErr(StatusCode::NOT_FOUND, "conflit introuvable".into()))?;
    match &c.loser.val {
        Some(v) => {
            let v = model::validate(&c.col, v.clone()).map_err(bad)?;
            app.store.put_as(&c.col, &c.id, v, &format!("{} (résolution de conflit)", actor.0));
        }
        None => app.store.delete_as(&c.col, &c.id, &format!("{} (résolution de conflit)", actor.0)),
    }
    app.store.resolve_conflict(&cid);
    Ok(Json(json!({"ok": true})))
}

async fn conflicts_clear(State(app): State<Arc<App>>) -> Res {
    app.store.clear_resolved_conflicts();
    Ok(Json(json!({"ok": true})))
}

// ---------- maintenance ----------

pub const TOMBSTONE_MIN_AGE_MS: u64 = 7 * 24 * 3600 * 1000;

pub fn peer_ids(app: &App) -> Vec<String> {
    app.node.lock().peers.iter().map(|p| p.id.clone()).collect()
}

async fn maintenance(State(app): State<Arc<App>>) -> Res {
    Ok(Json(json!({"tombstones": app.store.tombstone_count(), "min_age_days": TOMBSTONE_MIN_AGE_MS / 86_400_000, "peers": peer_ids(&app).len()})))
}

async fn maintenance_compact(State(app): State<Arc<App>>) -> Res {
    let removed = app.store.compact(TOMBSTONE_MIN_AGE_MS, &peer_ids(&app));
    app.store.save();
    Ok(Json(json!({"removed": removed, "tombstones": app.store.tombstone_count()})))
}

// ---------- jetons d'API ----------

fn token_view(id: &str, v: &Value, used: Option<(u64, String)>) -> Value {
    json!({
        "id": id,
        "name": v["name"],
        "prefix": v["prefix"],
        "scope": v["scope"],
        "ips": v["ips"],
        "expires_at": v["expires_at"],
        "created_at": v["created_at"],
        "last_used": used.as_ref().map(|u| u.0),
        "last_ip": used.map(|u| u.1),
    })
}

async fn tokens_list(State(app): State<Arc<App>>) -> Res {
    let used = app.token_used.lock().clone();
    let mut v: Vec<Value> = app.store.list("tokens").iter().map(|(id, val, _)| token_view(id, val, used.get(id).cloned())).collect();
    v.sort_by(|a, b| b["created_at"].as_u64().cmp(&a["created_at"].as_u64()));
    Ok(Json(Value::Array(v)))
}

#[derive(Deserialize)]
struct TokenReq {
    name: String,
    /// read | write
    scope: Option<String>,
    ips: Option<Vec<String>>,
    /// Durée de validité en jours (absent = sans expiration).
    expires_in_days: Option<u64>,
    expires_at: Option<u64>,
}

fn check_token_req(r: &TokenReq) -> Result<(String, String, Vec<String>), ApiErr> {
    let name = r.name.trim().to_string();
    if name.is_empty() {
        return Err(bad("le nom est obligatoire"));
    }
    let scope = r.scope.clone().unwrap_or_else(|| "read".into());
    if scope != "read" && scope != "write" {
        return Err(bad("portée inconnue (read ou write)"));
    }
    let ips: Vec<String> = r.ips.clone().unwrap_or_default().into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    for i in &ips {
        if crate::clients::Cidr::parse(i).is_none() {
            return Err(bad(format!("« {i} » n'est pas une adresse IP ni une plage CIDR valide")));
        }
    }
    Ok((name, scope, ips))
}

async fn token_create(State(app): State<Arc<App>>, Extension(actor): Extension<Actor>, Json(r): Json<TokenReq>) -> Res {
    let (name, scope, ips) = check_token_req(&r)?;
    let secret = format!("atm_{}", state::random_hex(20));
    let id = state::random_hex(4);
    let expires = r.expires_in_days.filter(|d| *d > 0).map(|d| now_ms() + d * 86_400_000);
    let v = json!({
        "name": name, "scope": scope, "ips": ips, "expires_at": expires, "created_at": now_ms(),
        "hash": crate::auth::token_hash(&secret), "prefix": &secret[..8],
    });
    app.store.put_as("tokens", &id, v.clone(), &actor.0);
    Ok(Json(json!({"token": secret, "id": id, "info": token_view(&id, &v, None)})))
}

async fn token_update(State(app): State<Arc<App>>, Extension(actor): Extension<Actor>, Path(id): Path<String>, Json(r): Json<TokenReq>) -> Res {
    let (name, scope, ips) = check_token_req(&r)?;
    let mut v = app.store.get("tokens", &id).ok_or_else(|| ApiErr(StatusCode::NOT_FOUND, "jeton introuvable".into()))?;
    v["name"] = json!(name);
    v["scope"] = json!(scope);
    v["ips"] = json!(ips);
    v["expires_at"] = json!(r.expires_at);
    app.store.put_as("tokens", &id, v, &actor.0);
    Ok(Json(json!({"ok": true})))
}

async fn token_delete(State(app): State<Arc<App>>, Extension(actor): Extension<Actor>, Path(id): Path<String>) -> Res {
    if app.store.get("tokens", &id).is_none() {
        return Err(ApiErr(StatusCode::NOT_FOUND, "jeton introuvable".into()));
    }
    app.store.delete_as("tokens", &id, &actor.0);
    app.token_used.lock().remove(&id);
    Ok(Json(json!({"ok": true})))
}

// ---------- test de résolution ----------

#[derive(Deserialize)]
struct ResolveReq {
    domain: String,
    #[serde(rename = "type")]
    qtype: Option<String>,
    client: Option<String>,
}

/// Résout un nom avec le moteur du nœud, comme le ferait un client, sans l'écrire dans le journal.
async fn resolve_test(State(app): State<Arc<App>>, Json(r): Json<ResolveReq>) -> Res {
    let name = model::norm_domain(&r.domain);
    if name.is_empty() {
        return Err(bad("domaine vide"));
    }
    let qtype = r.qtype.as_deref().and_then(dnswire::type_from_name).unwrap_or(dnswire::T_A);
    let client: std::net::IpAddr = r.client.as_deref().and_then(|c| c.trim().parse().ok()).unwrap_or_else(|| "127.0.0.1".parse().unwrap());
    let req = dnswire::build_query(0x5a5a, &name, qtype);
    let q = dnswire::parse_query(&req).ok_or_else(|| bad("nom invalide"))?;
    let t = std::time::Instant::now();
    let o = crate::resolver::resolve(&app, &req, &q, client).await;
    let info = dnswire::response_info(&o.resp).unwrap_or_default();
    let answers: Vec<String> = info
        .addrs
        .iter()
        .filter_map(|(t, rd, _)| if *t == dnswire::T_A && rd.len() == 4 { Some(format!("{}.{}.{}.{}", rd[0], rd[1], rd[2], rd[3])) } else if *t == dnswire::T_AAAA && rd.len() == 16 { let mut b = [0u8; 16]; b.copy_from_slice(rd); Some(std::net::Ipv6Addr::from(b).to_string()) } else { None })
        .collect();
    Ok(Json(json!({
        "result": o.result, "ad": o.ad, "reason": o.reason, "list": o.list, "upstream": o.upstream, "cached": o.cached,
        "rcode": info.rcode, "answers": answers, "ms": t.elapsed().as_millis() as u64,
    })))
}
