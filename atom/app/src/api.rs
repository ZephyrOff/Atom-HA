//! API HTTP (interface web, intégration Home Assistant, synchronisation entre nœuds).

use crate::dnswire::{self, Query};
use crate::engine::RwAns;
use crate::filter::{self, HitKind};
use crate::model::{self, ListCfg, Settings, UpstreamCfg};
use crate::state::{self, App, Peer, VERSION};
use crate::store::now_ms;
use crate::sync::{self, PullReq};
use crate::upstream;
use axum::extract::{ConnectInfo, Path, Query as QS, Request, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::Engine as _;
use rust_embed::RustEmbed;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(RustEmbed)]
#[folder = "ui/"]
struct Ui;

type Res = Result<Json<Value>, ApiErr>;

pub struct ApiErr(StatusCode, String);

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn bad(msg: impl Into<String>) -> ApiErr {
    ApiErr(StatusCode::BAD_REQUEST, msg.into())
}

fn not_found(msg: impl Into<String>) -> ApiErr {
    ApiErr(StatusCode::NOT_FOUND, msg.into())
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/api/info", get(info))
        .route("/api/c/{col}", get(list_col).post(create))
        .route("/api/c/{col}/{id}", put(update).delete(remove))
        .route("/api/upstreams/reorder", post(reorder))
        .route("/api/upstreams/status", get(upstream_status))
        .route("/api/upstreams/test", post(upstream_test_new))
        .route("/api/upstreams/{id}/test", post(upstream_test))
        .route("/api/lists/status", get(lists_status))
        .route("/api/lists/refresh", post(lists_refresh_all))
        .route("/api/lists/{id}/refresh", post(list_refresh))
        .route("/api/check", post(check))
        .route("/api/log", get(log))
        .route("/api/log/facets", get(log_facets))
        .route("/api/stats", get(stats))
        .route("/api/cache/flush", post(cache_flush))
        .route("/api/pause", post(pause))
        .route("/api/cluster", get(cluster))
        .route("/api/cluster/join", post(cluster_join))
        .route("/api/cluster/sync", post(cluster_sync))
        .route("/api/cluster/peers/{id}", delete(peer_remove))
        .route("/api/sync/pull", post(sync_pull))
        .route("/api/sync/hello", post(sync_hello))
        .route("/api/sync/notify", post(sync_notify))
        .fallback(static_files)
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(app.clone(), auth))
        .with_state(app)
}

// ---------- authentification ----------

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"Atom\", charset=\"UTF-8\"")],
        "Authentification requise",
    )
        .into_response()
}

async fn auth(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    if path.starts_with("/api/sync/") {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        let expected = app.node.lock().cluster_token.clone();
        if !state::ct_eq(token, &expected) {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "jeton de cluster invalide"}))).into_response();
        }
        return next.run(req).await;
    }
    if let (Some(trusted), Some(ci)) = (&app.cfg.trusted_ip, req.extensions().get::<ConnectInfo<SocketAddr>>()) {
        if &ci.0.ip().to_string() == trusted {
            return next.run(req).await;
        }
    }
    let ok = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b.trim()).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .map(|s| {
            let (user, pw) = s.split_once(':').unwrap_or((&s, ""));
            let n = app.node.lock();
            user == "admin" && state::ct_eq(&state::hash_password(&n.pw_salt, pw), &n.pw_hash)
        })
        .unwrap_or(false);
    if ok {
        next.run(req).await
    } else {
        unauthorized()
    }
}

// ---------- statique ----------

async fn static_files(uri: Uri) -> Response {
    let mut path = uri.path().trim_start_matches('/').to_string();
    if path.is_empty() {
        path = "index.html".into();
    }
    match Ui::get(&path) {
        Some(f) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            (
                [(header::CONTENT_TYPE, mime.to_string()), (header::CACHE_CONTROL, "no-cache".to_string())],
                f.data.into_owned(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "introuvable").into_response(),
    }
}

// ---------- général ----------

async fn info(State(app): State<Arc<App>>) -> Res {
    let eng = app.engine.load();
    let n = app.node.lock();
    Ok(Json(json!({
        "node_id": n.node_id,
        "name": n.name,
        "version": VERSION,
        "dns_listen": app.cfg.dns_listen,
        "dns_ok": app.dns_ok.load(std::sync::atomic::Ordering::Relaxed),
        "uptime_s": app.started.elapsed().as_secs(),
        "filtering_enabled": eng.settings.filtering_enabled,
        "paused_until": eng.settings.pause_until.filter(|t| *t > now_ms()),
        "rules_loaded": eng.lists.iter().map(|l| l.count).sum::<usize>(),
        "peers": n.peers.len(),
    })))
}

// ---------- collections ----------

fn check_col(col: &str) -> Result<(), ApiErr> {
    if model::COLLECTIONS.contains(&col) {
        Ok(())
    } else {
        Err(not_found("collection inconnue"))
    }
}

async fn list_col(State(app): State<Arc<App>>, Path(col): Path<String>) -> Res {
    check_col(&col)?;
    let items: Vec<Value> = app
        .store
        .list(&col)
        .into_iter()
        .map(|(id, mut v, hlc)| {
            if let Some(o) = v.as_object_mut() {
                o.insert("id".into(), json!(id));
                o.insert("updated_at".into(), json!(hlc.wall));
            }
            v
        })
        .collect();
    Ok(Json(Value::Array(items)))
}

async fn put_value(app: &Arc<App>, col: &str, id: &str, body: Value) -> Res {
    check_col(col)?;
    let mut body = body;
    if let Some(o) = body.as_object_mut() {
        o.remove("id");
        o.remove("updated_at");
    }
    let v = model::validate(col, body).map_err(bad)?;
    app.store.put(col, id, v.clone());
    if col == "lists" {
        let (a, id) = (app.clone(), id.to_string());
        tokio::spawn(async move {
            let _ = crate::lists::refresh(&a, &id, true).await;
        });
    }
    Ok(Json(json!({"id": id, "value": v})))
}

async fn create(State(app): State<Arc<App>>, Path(col): Path<String>, Json(body): Json<Value>) -> Res {
    let id = state::random_hex(4);
    put_value(&app, &col, &id, body).await
}

async fn update(State(app): State<Arc<App>>, Path((col, id)): Path<(String, String)>, Json(body): Json<Value>) -> Res {
    put_value(&app, &col, &id, body).await
}

async fn remove(State(app): State<Arc<App>>, Path((col, id)): Path<(String, String)>) -> Res {
    check_col(&col)?;
    if col == "settings" {
        return Err(bad("les réglages ne peuvent pas être supprimés"));
    }
    if col == "zones" {
        if let Some(z) = app.store.get("zones", &id) {
            let zname = z.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            for (rid, rv, _) in app.store.list("records") {
                if rv.get("zone").and_then(|v| v.as_str()) == Some(&zname) {
                    app.store.delete("records", &rid);
                }
            }
        }
    }
    app.store.delete(&col, &id);
    Ok(Json(json!({"ok": true})))
}

// ---------- upstreams ----------

#[derive(Deserialize)]
struct ReorderReq {
    ids: Vec<String>,
}

async fn reorder(State(app): State<Arc<App>>, Json(r): Json<ReorderReq>) -> Res {
    for (i, id) in r.ids.iter().enumerate() {
        let Some(v) = app.store.get("upstreams", id) else { continue };
        let Ok(mut u) = serde_json::from_value::<UpstreamCfg>(v) else { continue };
        let order = (i + 1) as f64;
        if (u.order - order).abs() > f64::EPSILON {
            u.order = order;
            app.store.put("upstreams", id, serde_json::to_value(&u).unwrap_or_default());
        }
    }
    Ok(Json(json!({"ok": true})))
}

async fn upstream_status(State(app): State<Arc<App>>) -> Res {
    let h = app.health.lock().clone();
    Ok(Json(serde_json::to_value(h).unwrap_or_default()))
}

async fn run_probe(app: &Arc<App>, id: &str, cfg: &UpstreamCfg) -> Res {
    let u = upstream::Upstream::new(id, &cfg.name, &cfg.address, &cfg.bootstrap, cfg.order, cfg.domains.clone())
        .map_err(|e| bad(e.to_string()))?;
    let health = if id == "tmp" { Default::default() } else { app.health.clone() };
    match upstream::probe(&u, &health).await {
        Ok(ms) => Ok(Json(json!({"ok": true, "latency_ms": ms}))),
        Err(e) => Ok(Json(json!({"ok": false, "error": e}))),
    }
}

async fn upstream_test(State(app): State<Arc<App>>, Path(id): Path<String>) -> Res {
    let cfg: UpstreamCfg = app
        .store
        .get("upstreams", &id)
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or_else(|| not_found("upstream introuvable"))?;
    run_probe(&app, &id, &cfg).await
}

async fn upstream_test_new(State(app): State<Arc<App>>, Json(cfg): Json<UpstreamCfg>) -> Res {
    run_probe(&app, "tmp", &cfg).await
}

// ---------- listes ----------

async fn lists_status(State(app): State<Arc<App>>) -> Res {
    let m = app.lists_meta.lock().clone();
    Ok(Json(serde_json::to_value(m).unwrap_or_default()))
}

async fn list_refresh(State(app): State<Arc<App>>, Path(id): Path<String>) -> Res {
    match crate::lists::refresh(&app, &id, true).await {
        Ok(()) => Ok(Json(json!({"ok": true}))),
        Err(e) => Ok(Json(json!({"ok": false, "error": e.to_string()}))),
    }
}

async fn lists_refresh_all(State(app): State<Arc<App>>) -> Res {
    let mut errors = vec![];
    for (id, v, _) in app.store.list("lists") {
        if let Ok(l) = serde_json::from_value::<ListCfg>(v) {
            if l.kind == "url" && l.enabled {
                if let Err(e) = crate::lists::refresh(&app, &id, true).await {
                    errors.push(format!("{} : {e}", l.name));
                }
            }
        }
    }
    Ok(Json(json!({"ok": errors.is_empty(), "errors": errors})))
}

// ---------- test d'un domaine ----------

#[derive(Deserialize)]
struct CheckReq {
    domain: String,
}

async fn check(State(app): State<Arc<App>>, Json(r): Json<CheckReq>) -> Res {
    let name = model::norm_domain(&r.domain);
    if name.is_empty() {
        return Err(bad("domaine vide"));
    }
    let eng = app.engine.load_full();
    let q = Query { id: 0, rd: true, name: name.clone(), qtype: dnswire::T_A, qclass: 1, qend: 0, edns_size: None };
    if eng.settings.rewrites_enabled {
        if let Some(rw) = eng.rewrite_lookup(&name, now_ms()) {
            let a = rw
                .iter()
                .map(|e| match &e.ans {
                    RwAns::Ip(ip) => ip.to_string(),
                    RwAns::Cname(c) => c.clone(),
                })
                .collect::<Vec<_>>()
                .join(", ");
            return Ok(Json(json!({"result": "rewritten", "detail": format!("réécriture DNS vers {a}")})));
        }
    }
    if let Some(z) = eng.zone_answer(&q) {
        let nx = z.rcode == dnswire::RC_NXDOMAIN;
        return Ok(Json(json!({"result": "zone", "detail": if nx { "NXDOMAIN (zone locale)" } else { "répondu par une zone locale" }})));
    }
    match filter::check(&eng.lists, &name) {
        Some(h) => {
            let result = match &h.kind {
                HitKind::Block => "blocked",
                HitKind::Allow => "allowed",
                HitKind::Rewrite(_) => "rewritten",
            };
            Ok(Json(json!({"result": result, "rule": h.rule, "list": h.list})))
        }
        None => Ok(Json(json!({"result": "allowed", "detail": "aucune règle ne correspond"}))),
    }
}

// ---------- journal et statistiques ----------

#[derive(Deserialize, Default)]
struct LogParams {
    search: Option<String>,
    status: Option<String>,
    node: Option<String>,
    client: Option<String>,
    qtype: Option<String>,
    limit: Option<usize>,
    before: Option<u64>,
    from: Option<u64>,
    to: Option<u64>,
}

async fn log_facets(State(app): State<Arc<App>>) -> Res {
    Ok(Json(serde_json::to_value(app.qlog.facets()).unwrap_or_default()))
}

async fn log(State(app): State<Arc<App>>, QS(p): QS<LogParams>) -> Res {
    let f = crate::qlog::LogFilter {
        search: p.search.unwrap_or_default(),
        status: p.status.unwrap_or_default(),
        node: p.node.unwrap_or_default(),
        client: p.client.unwrap_or_default(),
        qtype: p.qtype.unwrap_or_default(),
        limit: p.limit.unwrap_or(100),
        before: p.before,
        from: p.from,
        to: p.to,
    };
    Ok(Json(serde_json::to_value(app.qlog.query(&f)).unwrap_or_default()))
}

#[derive(Deserialize, Default)]
struct StatsParams {
    node: Option<String>,
}

async fn stats(State(app): State<Arc<App>>, QS(p): QS<StatsParams>) -> Res {
    let s = app.qlog.stats(&p.node.unwrap_or_default());
    let mut v = serde_json::to_value(&s).unwrap_or_default();
    // noms lisibles des nœuds
    let mut names: HashMap<String, String> = HashMap::new();
    names.insert(app.node_id(), app.node_name());
    for (id, st) in app.peer_status.lock().iter() {
        names.insert(id.clone(), st.name.clone());
    }
    v["node_names"] = json!(names);
    Ok(Json(v))
}

async fn cache_flush(State(app): State<Arc<App>>) -> Res {
    app.cache.lock().clear();
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct PauseReq {
    minutes: Option<u64>,
}

async fn pause(State(app): State<Arc<App>>, Json(r): Json<PauseReq>) -> Res {
    let mut s: Settings = app
        .store
        .get("settings", "main")
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    s.pause_until = r.minutes.filter(|m| *m > 0).map(|m| now_ms() + m * 60_000);
    app.store.put("settings", "main", serde_json::to_value(&s).unwrap_or_default());
    Ok(Json(json!({"ok": true, "pause_until": s.pause_until})))
}

// ---------- cluster ----------

async fn cluster(State(app): State<Arc<App>>) -> Res {
    let n = app.node.lock().clone();
    let st = app.peer_status.lock().clone();
    let peers: Vec<Value> = n
        .peers
        .iter()
        .map(|p| {
            let s = st.get(&p.id).cloned().unwrap_or_default();
            json!({"id": p.id, "name": if s.name.is_empty() { p.name.clone() } else { s.name.clone() }, "url": p.url,
                   "ok": s.ok, "last_ok": s.last_ok, "latency_ms": s.latency_ms, "error": s.last_error})
        })
        .collect();
    Ok(Json(json!({
        "node": {"id": n.node_id, "name": n.name, "advertise_url": n.advertise_url},
        "token": n.cluster_token,
        "peers": peers,
    })))
}

#[derive(Deserialize)]
struct JoinReq {
    url: String,
    token: String,
    self_url: String,
}

async fn cluster_join(State(app): State<Arc<App>>, Json(r): Json<JoinReq>) -> Res {
    let url = r.url.trim().trim_end_matches('/').to_string();
    let self_url = r.self_url.trim().trim_end_matches('/').to_string();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(bad("l'adresse de l'autre nœud doit commencer par http:// ou https://"));
    }
    if !(self_url.starts_with("http://") || self_url.starts_with("https://")) {
        return Err(bad("l'adresse de ce nœud doit commencer par http:// ou https://"));
    }
    let (id, name) = {
        let n = app.node.lock();
        (n.node_id.clone(), n.name.clone())
    };
    let resp = app
        .http
        .post(format!("{url}/api/sync/hello"))
        .bearer_auth(r.token.trim())
        .timeout(std::time::Duration::from_secs(10))
        .json(&json!({"id": id, "name": name, "url": self_url}))
        .send()
        .await
        .map_err(|e| bad(format!("connexion impossible : {e}")))?;
    if resp.status() == StatusCode::UNAUTHORIZED {
        return Err(bad("code d'appairage refusé"));
    }
    if !resp.status().is_success() {
        return Err(bad(format!("l'autre nœud a répondu {}", resp.status())));
    }
    let remote: Value = resp.json().await.map_err(|e| bad(e.to_string()))?;
    let rid = remote["id"].as_str().unwrap_or("").to_string();
    let rname = remote["name"].as_str().unwrap_or("").to_string();
    if rid.is_empty() || rid == id {
        return Err(bad("réponse invalide de l'autre nœud"));
    }
    {
        let mut n = app.node.lock();
        n.cluster_token = r.token.trim().to_string();
        n.advertise_url = self_url;
        n.peers.retain(|p| p.id != rid);
        n.peers.push(Peer { id: rid, name: rname, url });
    }
    app.save_node();
    app.sync_wake.notify_one();
    Ok(Json(json!({"ok": true})))
}

async fn cluster_sync(State(app): State<Arc<App>>) -> Res {
    sync::sync_once(&app).await;
    Ok(Json(json!({"ok": true})))
}

async fn peer_remove(State(app): State<Arc<App>>, Path(id): Path<String>) -> Res {
    app.node.lock().peers.retain(|p| p.id != id);
    app.peer_status.lock().remove(&id);
    app.save_node();
    Ok(Json(json!({"ok": true})))
}

// ---------- points d'entrée pour les pairs ----------

async fn sync_pull(State(app): State<Arc<App>>, Json(r): Json<PullReq>) -> Res {
    Ok(Json(serde_json::to_value(sync::answer_pull(&app, r)).unwrap_or_default()))
}

#[derive(Deserialize)]
struct Hello {
    id: String,
    name: String,
    url: String,
}

async fn sync_hello(State(app): State<Arc<App>>, Json(h): Json<Hello>) -> Res {
    if h.id == app.node_id() {
        return Err(bad("ce nœud est déjà celui-ci"));
    }
    {
        let mut n = app.node.lock();
        n.peers.retain(|p| p.id != h.id);
        n.peers.push(Peer { id: h.id, name: h.name, url: h.url.trim_end_matches('/').to_string() });
    }
    app.save_node();
    app.sync_wake.notify_one();
    Ok(Json(json!({"id": app.node_id(), "name": app.node_name()})))
}

async fn sync_notify(State(app): State<Arc<App>>, _h: HeaderMap) -> Res {
    app.sync_wake.notify_one();
    Ok(Json(json!({"ok": true})))
}
