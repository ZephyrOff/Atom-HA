//! API : autorisations temporaires, recherche globale, santé du cluster, tâches de fond (certificats, nettoyage).

use crate::api::{bad, Actor, CheckReq, Res};
use crate::model;
use crate::state::{App, VERSION};
use crate::store::now_ms;
use crate::tls;
use axum::extract::{Query as QS, State};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/tempallow", post(tempallow_create))
        .route("/api/search", get(search))
        .route("/api/health", get(health))
}

// ---------- autorisation temporaire ----------

#[derive(Deserialize)]
struct TempReq {
    domain: String,
    /// Durée en minutes (de 1 minute à 30 jours).
    minutes: u64,
    note: Option<String>,
}

async fn tempallow_create(State(app): State<Arc<App>>, Extension(actor): Extension<Actor>, Json(r): Json<TempReq>) -> Res {
    let domain = model::norm_domain(&r.domain);
    if !model::valid_hostname(&domain) {
        return Err(bad("domaine invalide"));
    }
    if r.minutes == 0 || r.minutes > 30 * 24 * 60 {
        return Err(bad("la durée doit être comprise entre 1 minute et 30 jours"));
    }
    let until = now_ms() + r.minutes * 60_000;
    let v = model::validate("tempallow", json!({"domain": domain, "until": until, "note": r.note.unwrap_or_default()})).map_err(bad)?;
    app.store.put_as("tempallow", &domain, v, &actor.0);
    Ok(Json(json!({"ok": true, "domain": domain, "until": until})))
}

/// Retire les autorisations expirées depuis quelques minutes.
fn purge_tempallow(app: &Arc<App>) {
    let limit = now_ms().saturating_sub(5 * 60_000);
    for (id, v, _) in app.store.list("tempallow") {
        if v["until"].as_u64().map_or(true, |u| u < limit) {
            app.store.delete_as("tempallow", &id, "expiration");
        }
    }
}

// ---------- recherche globale ----------

#[derive(Deserialize)]
struct SearchQ {
    q: String,
}

fn hit(kind: &str, title: impl Into<String>, detail: impl Into<String>, route: impl Into<String>) -> Value {
    json!({"kind": kind, "title": title.into(), "detail": detail.into(), "route": route.into()})
}

fn has(q: &str, fields: &[&str]) -> bool {
    fields.iter().any(|f| f.to_lowercase().contains(q))
}

async fn search(State(app): State<Arc<App>>, QS(p): QS<SearchQ>) -> Res {
    let raw = p.q.trim();
    if raw.is_empty() {
        return Ok(Json(json!({"verdict": null, "results": []})));
    }
    let q = raw.to_lowercase();
    let s = |v: &Value, k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mut out: Vec<Value> = Vec::new();

    // Ce qui arriverait à ce nom : bloqué, autorisé, réécrit, zone locale…
    let name = model::norm_domain(raw);
    let verdict = if model::valid_hostname(&name) && name.contains('.') {
        crate::api::check(State(app.clone()), Json(CheckReq { domain: name.clone(), client: None, qtype: None })).await.ok().map(|j| j.0)
    } else {
        None
    };

    for (_, v, _) in app.store.list("rules") {
        for line in s(&v, "text").lines().map(str::trim).filter(|l| !l.is_empty() && l.to_lowercase().contains(&q)).take(8) {
            out.push(hit("Règle personnalisée", line, "", "rules"));
        }
    }
    for (id, v, _) in app.store.list("rewrites") {
        let (d, a) = (s(&v, "domain"), s(&v, "answer"));
        if has(&q, &[&d, &a]) {
            out.push(hit("Réécriture", format!("{d} → {a}"), if v["enabled"].as_bool().unwrap_or(false) { "" } else { "désactivée" }, format!("rewrites#{id}")));
        }
    }
    for (_, v, _) in app.store.list("zones") {
        let n = s(&v, "name");
        if has(&q, &[&n]) {
            out.push(hit("Zone", n, "", "records"));
        }
    }
    for (_, v, _) in app.store.list("records") {
        let (zone, name, ty, val) = (s(&v, "zone"), s(&v, "name"), s(&v, "type"), s(&v, "value"));
        let fq = model::record_fqdn(&zone, &name);
        if has(&q, &[&fq, &val]) {
            out.push(hit("Enregistrement", format!("{fq} {ty} {val}"), "", "records"));
        }
    }
    for (_, v, _) in app.store.list("lists") {
        let (n, u) = (s(&v, "name"), s(&v, "url"));
        if has(&q, &[&n, &u]) {
            out.push(hit("Liste de filtrage", n, u, "filters"));
        }
    }
    for (_, v, _) in app.store.list("upstreams") {
        let (n, a) = (s(&v, "name"), s(&v, "address"));
        if has(&q, &[&n, &a]) {
            out.push(hit("Upstream", n, a, "dns"));
        }
    }
    for (id, v, _) in app.store.list("clients") {
        let ids = v["ids"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
        let (n, notes) = (s(&v, "name"), s(&v, "notes"));
        if has(&q, &[&n, &ids, &notes]) {
            out.push(hit("Client", n, ids, format!("client/{id}")));
        }
    }
    for (id, v, _) in app.store.list("groups") {
        let (n, d) = (s(&v, "name"), s(&v, "description"));
        if has(&q, &[&n, &d]) {
            out.push(hit("Groupe", n, d, format!("group/{id}")));
        }
    }
    let now = now_ms();
    for (_, v, _) in app.store.list("tempallow") {
        let d = s(&v, "domain");
        if has(&q, &[&d]) && v["until"].as_u64().map_or(false, |u| u > now) {
            out.push(hit("Autorisation temporaire", d, "", "rules"));
        }
    }
    for (_, v, _) in app.store.list("tokens") {
        let n = s(&v, "name");
        if has(&q, &[&n]) {
            out.push(hit("Jeton d'API", n, "", "security"));
        }
    }
    out.truncate(60);
    Ok(Json(json!({"verdict": verdict.map(|mut v| { v["domain"] = json!(name); v }), "results": out})))
}

// ---------- santé du cluster ----------

fn days_left(ms: u64, now: u64) -> i64 {
    (ms as i64 - now as i64).div_euclid(86_400_000)
}

fn cert_problem(problems: &mut Vec<Value>, scope: &str, what: &str, exp: Option<u64>, now: u64) {
    let Some(exp) = exp else { return };
    let d = days_left(exp, now);
    if d < 0 {
        problems.push(json!({"level": "bad", "scope": scope, "text": format!("{what} expiré")}));
    } else if d < 7 {
        problems.push(json!({"level": "bad", "scope": scope, "text": format!("{what} expire dans {d} jour(s)")}));
    } else if d < 30 {
        problems.push(json!({"level": "warn", "scope": scope, "text": format!("{what} expire dans {d} jours")}));
    }
}

async fn health(State(app): State<Arc<App>>) -> Res {
    let now = now_ms();
    let (me_id, me_name, mode, peers, web_generated) = {
        let n = app.node.lock();
        (n.node_id.clone(), n.name.clone(), n.tls.cluster_mode.clone(), n.peers.clone(), n.tls.web_generated)
    };
    let mut problems: Vec<Value> = Vec::new();
    let info_of = |name: &str| tls::read(&app, name).and_then(|p| tls::cert_info(&p).ok()).map(|i| i.not_after);
    let node_cert = tls::own_cert_expiry(&app);
    let ca_cert = if mode != "off" { info_of("ca.crt") } else { None };
    let web_cert = if app.node.lock().tls.web_enabled { info_of("web.crt") } else { None };

    // ce nœud
    let dns_ok = app.dns_ok.load(std::sync::atomic::Ordering::Relaxed);
    if !dns_ok {
        problems.push(json!({"level": "bad", "scope": me_name, "text": "le serveur DNS de ce nœud n'écoute pas"}));
    }
    cert_problem(&mut problems, &me_name, "le certificat du nœud", node_cert, now);
    cert_problem(&mut problems, &me_name, "le certificat de l'autorité", ca_cert.filter(|_| mode != "pki"), now);
    cert_problem(&mut problems, &me_name, "le certificat de l'interface web", web_cert, now);
    {
        let eng = app.engine.load();
        let h = app.health.lock();
        let total = eng.upstreams.len();
        let down: Vec<&str> = eng.upstreams.iter().filter(|u| h.get(&u.id).map_or(false, |x| x.up == Some(false))).map(|u| u.name.as_str()).collect();
        if total > 0 && down.len() == total {
            problems.push(json!({"level": "bad", "scope": me_name, "text": "tous les upstreams sont injoignables"}));
        } else if !down.is_empty() {
            problems.push(json!({"level": "warn", "scope": me_name, "text": format!("upstream injoignable : {}", down.join(", "))}));
        }
    }
    for (id, m) in app.lists_meta.lock().iter() {
        if let (Some(e), Some(l)) = (&m.error, app.store.get("lists", id)) {
            problems.push(json!({"level": "warn", "scope": me_name, "text": format!("liste « {} » : {e}", l["name"].as_str().unwrap_or(id))}));
        }
    }

    // les autres nœuds
    let status = app.peer_status.lock().clone();
    let mut plist: Vec<Value> = Vec::new();
    for p in &peers {
        let st = status.get(&p.id).cloned().unwrap_or_default();
        let name = if st.name.is_empty() { p.name.clone() } else { st.name.clone() };
        let age = if st.last_ok > 0 { now.saturating_sub(st.last_ok) } else { u64::MAX };
        if st.last_ok == 0 && !st.ok {
            problems.push(json!({"level": "bad", "scope": name, "text": format!("nœud jamais joint{}", st.last_error.as_ref().map(|e| format!(" ({e})")).unwrap_or_default())}));
        } else if !st.ok {
            let lvl = if age > 5 * 60_000 { "bad" } else { "warn" };
            problems.push(json!({"level": lvl, "scope": name, "text": format!("injoignable depuis {} min{}", age / 60_000, st.last_error.as_ref().map(|e| format!(" ({e})")).unwrap_or_default())}));
        }
        if st.ok {
            if st.version.is_empty() {
                problems.push(json!({"level": "warn", "scope": name, "text": format!("version plus ancienne que {VERSION} (ce nœud ne publie pas sa version)")}));
            } else if st.version != VERSION {
                problems.push(json!({"level": "warn", "scope": name, "text": format!("version {} alors que ce nœud est en {VERSION} : mets-les à jour ensemble pour éviter des comportements différents", st.version)}));
            }
            let skew = st.skew_ms.unsigned_abs();
            if skew > 60_000 {
                problems.push(json!({"level": "bad", "scope": name, "text": format!("horloge décalée de {} s : la synchro et les certificats en dépendent", skew / 1000)}));
            } else if skew > 5_000 {
                problems.push(json!({"level": "warn", "scope": name, "text": format!("horloge décalée de {} s", skew / 1000)}));
            }
            if st.dns_ok == Some(false) {
                problems.push(json!({"level": "bad", "scope": name, "text": "le serveur DNS de ce nœud n'écoute pas"}));
            }
            if st.behind_ops > 100 {
                problems.push(json!({"level": "warn", "scope": name, "text": format!("{} modification(s) pas encore reçues par ce nœud", st.behind_ops)}));
            }
            cert_problem(&mut problems, &name, "son certificat de nœud", st.cert_expires, now);
        }
        plist.push(json!({
            "id": p.id, "name": name, "url": p.url, "ok": st.ok, "last_ok": st.last_ok, "latency_ms": st.latency_ms,
            "version": st.version, "skew_ms": st.skew_ms, "cert_expires": st.cert_expires, "dns_ok": st.dns_ok,
            "behind_ops": st.behind_ops, "last_error": st.last_error,
        }));
    }
    problems.sort_by_key(|p| if p["level"] == "bad" { 0 } else { 1 });
    let cert_log: Vec<Value> = app.cert_log.lock().iter().rev().map(|(t, m)| json!({"ts": t, "text": m})).collect();
    Ok(Json(json!({
        "self": {
            "id": me_id, "name": me_name, "version": VERSION, "uptime_s": app.started.elapsed().as_secs(), "dns_ok": dns_ok,
            "cert_expires": node_cert, "ca_expires": ca_cert, "web_expires": web_cert, "cluster_mode": mode,
            "web_auto": web_generated, "node_auto": mode == "ca" || mode == "selfsigned",
        },
        "peers": plist,
        "problems": problems,
        "cert_log": cert_log,
    })))
}

// ---------- tâches de fond ----------

const RENEW_BEFORE_MS: u64 = 30 * 86_400_000;

fn note(app: &Arc<App>, text: String) {
    let mut g = app.cert_log.lock();
    let now = now_ms();
    if g.last().map_or(false, |(t, m)| *m == text && now.saturating_sub(*t) < 24 * 3_600_000) {
        return;
    }
    tracing::info!("certificats : {text}");
    g.push((now, text));
    let n = g.len();
    if n > 20 {
        g.drain(..n - 20);
    }
}

async fn certs_check(app: &Arc<App>) {
    let now = now_ms();
    let mode = app.node.lock().tls.cluster_mode.clone();
    if mode == "ca" || mode == "selfsigned" {
        if let Some(exp) = tls::own_cert_expiry(app).filter(|e| *e < now + RENEW_BEFORE_MS) {
            match crate::api_tls::renew_node(app).await {
                Ok(()) => note(app, "certificat du nœud renouvelé automatiquement".into()),
                Err(e) => note(app, format!("renouvellement automatique du certificat du nœud impossible : {} (échéance dans {} jour(s))", e.1, days_left(exp, now))),
            }
        }
    }
    let web_exp = tls::read(app, "web.crt").and_then(|p| tls::cert_info(&p).ok()).map(|i| i.not_after);
    if let Some(exp) = web_exp.filter(|e| *e < now + RENEW_BEFORE_MS) {
        match crate::api_tls::renew_web(app) {
            Ok(true) => note(app, "certificat de l'interface web renouvelé automatiquement".into()),
            Ok(false) => note(app, format!("le certificat de l'interface web expire dans {} jour(s) : il a été importé, renouvelle-le toi-même", days_left(exp, now))),
            Err(e) => note(app, format!("renouvellement automatique du certificat de l'interface impossible : {}", e.1)),
        }
    }
}

/// Renouvelle les certificats générés par Atom avant leur échéance et nettoie les autorisations temporaires échues.
pub async fn run(app: Arc<App>) {
    let a = app.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            purge_tempallow(&a);
        }
    });
    tokio::time::sleep(Duration::from_secs(90)).await;
    loop {
        certs_check(&app).await;
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
