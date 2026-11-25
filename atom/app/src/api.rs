//! API HTTP (interface web, intégration Home Assistant, synchronisation entre nœuds).

use crate::auth;
use crate::clients::{ClientSet, Identity};
use crate::dnswire::{self, Query};
use crate::engine::RwAns;
use crate::filter::{self, HitKind};
use crate::model::{self, ClientCfg, ListCfg, Settings, UpstreamCfg};
use crate::state::{self, App, Peer, VERSION};
use crate::store::now_ms;
use crate::sync::{self, PullReq};
use crate::upstream;
use axum::extract::{ConnectInfo, Path, Query as QS, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use rust_embed::RustEmbed;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(RustEmbed)]
#[folder = "ui/"]
struct Ui;

pub type Res = Result<Json<Value>, ApiErr>;

#[derive(Clone)]
pub struct Actor(pub String);

pub struct ApiErr(pub StatusCode, pub String);

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

pub fn bad(msg: impl Into<String>) -> ApiErr {
    ApiErr(StatusCode::BAD_REQUEST, msg.into())
}

fn not_found(msg: impl Into<String>) -> ApiErr {
    ApiErr(StatusCode::NOT_FOUND, msg.into())
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(me))
        .route("/api/auth/password", post(change_password))
        .route("/api/auth/revoke-others", post(revoke_others))
        .route("/api/auth/events", get(auth_events))
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
        .route("/api/cache", get(cache_list))
        .route("/api/cache/delete", post(cache_delete))
        .route("/api/cache/flush", post(cache_flush))
        .route("/api/clients", get(clients_list))
        .route("/api/pause", post(pause))
        .route("/api/cluster", get(cluster))
        .route("/api/cluster/join", post(cluster_join))
        .route("/api/cluster/sync", post(cluster_sync))
        .route("/api/cluster/peers/{id}", delete(peer_remove))
        .route("/api/sync/pull", post(sync_pull))
        .route("/api/sync/hello", post(sync_hello))
        .route("/api/sync/notify", post(sync_notify))
        .merge(crate::api_extra::routes())
        .merge(crate::api_tls::routes())
        .fallback(static_files)
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(app.clone(), auth))
        .with_state(app)
}

// ---------- authentification ----------

/// Fichiers et routes accessibles sans session.
const PUBLIC: &[&str] = &["/login.html", "/login.js", "/theme.js", "/style.css", "/logo.png", "/api/auth/login", "/api/auth/me"];

fn is_trusted_proxy(app: &App, peer: &SocketAddr) -> bool {
    let p = peer.ip().to_string();
    app.cfg.trusted_proxies.iter().any(|t| *t == p)
}

/// Adresse du client, en tenant compte d'un reverse proxy déclaré.
fn client_ip(app: &App, peer: &SocketAddr, h: &HeaderMap) -> String {
    if is_trusted_proxy(app, peer) {
        if let Some(first) = h
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
        {
            if first.parse::<std::net::IpAddr>().is_ok() {
                return first.to_string();
            }
        }
    }
    peer.ip().to_string()
}

fn session_token(h: &HeaderMap) -> Option<String> {
    let c = h.get(header::COOKIE)?.to_str().ok()?;
    c.split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == auth::COOKIE)
        .map(|(_, v)| v.to_string())
}

fn cookie_value(token: &str, max_age: u64, secure: bool) -> String {
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        auth::COOKIE,
        token,
        max_age,
        if secure { "; Secure" } else { "" }
    )
}

fn too_many(wait: Duration) -> Response {
    let s = wait.as_secs() + 1;
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, s.to_string())],
        Json(json!({"error": format!("Trop de tentatives. Réessaie dans {s} s."), "retry_after": s})),
    )
        .into_response()
}

/// Une requête qui modifie l'état doit venir de l'interface elle-même.
fn csrf_ok(h: &HeaderMap) -> bool {
    if let Some(origin) = h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let host = h.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
        if origin.split_once("://").map_or(true, |(_, rest)| rest != host) {
            return false;
        }
    }
    h.get("x-atom").is_some()
}

fn add_security_headers(h: &mut HeaderMap, ingress: bool) {
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    let mut csp = String::from(
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'",
    );
    if !ingress {
        // Dans l'ingress, Home Assistant affiche l'interface dans un cadre.
        csp.push_str("; frame-ancestors 'none'");
        h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    }
    if let Ok(v) = HeaderValue::from_str(&csp) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}

async fn auth(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
    let ingress = match (&app.cfg.trusted_ip, &peer) {
        (Some(t), Some(p)) => *t == p.ip().to_string(),
        _ => false,
    };
    let mut resp = gate(&app, req, next, peer, ingress).await;
    add_security_headers(resp.headers_mut(), ingress);
    resp
}

async fn gate(app: &Arc<App>, mut req: Request, next: Next, peer: Option<SocketAddr>, ingress: bool) -> Response {
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let unsafe_method = !matches!(*req.method(), axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS);
    let ip = peer.map(|p| client_ip(app, &p, &headers)).unwrap_or_default();

    let is_tls = req.extensions().get::<crate::tls::IsTls>().is_some();
    let peer_cert = req.extensions().get::<crate::tls::PeerCert>().cloned();

    // Redirection de l'interface vers HTTPS quand elle est demandée.
    if !is_tls && !ingress && !path.starts_with("/api/sync/") {
        let st = app.node.lock().tls.clone();
        let port = *app.tls_listening.lock();
        if let (true, Some(port)) = (st.redirect_http, port) {
            let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
            let bare = host.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map_or(host, |(h, _)| h);
            let target = if st.hostname.is_empty() { bare.to_string() } else { st.hostname.clone() };
            let pq = req.uri().path_and_query().map_or("/", |p| p.as_str());
            if let Ok(loc) = HeaderValue::from_str(&format!("https://{target}:{port}{pq}")) {
                let mut r = StatusCode::PERMANENT_REDIRECT.into_response();
                r.headers_mut().insert(header::LOCATION, loc);
                return r;
            }
        }
    }

    // Synchronisation entre nœuds : jeton de cluster, avec la même protection.
    if path.starts_with("/api/sync/") {
        // Quand le chiffrement du cluster est actif, seul un nœud présentant un certificat valide est reçu
        // (sauf pour l'appairage, qui se fait avec le code et sans certificat).
        let mode = app.node.lock().tls.cluster_mode.clone();
        let open_route = path == "/api/sync/enroll" || path == "/api/sync/tlsinfo";
        if mode != "off" && !open_route && peer_cert.is_none() {
            app.auth.event(&ip, "sync_fail", "certificat de nœud requis");
            return (StatusCode::FORBIDDEN, Json(json!({"error": "certificat de nœud requis (chiffrement du cluster activé)"}))).into_response();
        }
        if let Some(w) = app.auth.locked(&ip) {
            return too_many(w);
        }
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        let expected = app.node.lock().cluster_token.clone();
        if !state::ct_eq(token, &expected) {
            app.auth.failure(&ip);
            app.auth.event(&ip, "sync_fail", "jeton de cluster invalide");
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "jeton de cluster invalide"}))).into_response();
        }
        if let Some(pc) = &peer_cert {
            tracing::debug!("synchro reçue de {} (empreinte {})", pc.subject, pc.fingerprint);
        }
        return next.run(req).await;
    }

    // Jeton d'API : accès programmatique, sans cookie ni contrôle d'origine.
    if let Some(tok) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| t.starts_with("atm_"))
    {
        if let Some(w) = app.auth.locked(&ip) {
            return too_many(w);
        }
        return match check_api_token(app, tok, &ip, unsafe_method, &path) {
            Ok(name) => {
                req.extensions_mut().insert(Actor(format!("jeton {name}")));
                next.run(req).await
            }
            Err((status, msg)) => {
                if status == StatusCode::UNAUTHORIZED {
                    app.auth.failure(&ip);
                    app.auth.event(&ip, "login_fail", "jeton d'API invalide");
                }
                (status, Json(json!({"error": msg}))).into_response()
            }
        };
    }

    if !ingress && unsafe_method && !csrf_ok(&headers) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "requête refusée (origine)"}))).into_response();
    }

    let public = PUBLIC.contains(&path.as_str());
    let session_ok = session_token(&headers).map_or(false, |t| app.auth.validate(&t));
    if !(public || ingress || session_ok) {
        return if path.starts_with("/api/") {
            (StatusCode::UNAUTHORIZED, Json(json!({"error": "authentification requise"}))).into_response()
        } else {
            (StatusCode::FOUND, [(header::LOCATION, "login.html")]).into_response()
        };
    }
    let actor = if ingress {
        "admin (Home Assistant)"
    } else if session_ok {
        "admin"
    } else {
        "anonyme"
    };
    req.extensions_mut().insert(Actor(actor.into()));
    next.run(req).await
}

/// Vérifie un jeton d'API : existence, expiration, adresse du client, portée.
fn check_api_token(app: &Arc<App>, tok: &str, ip: &str, unsafe_method: bool, path: &str) -> Result<String, (StatusCode, String)> {
    let denied = |m: &str| (StatusCode::UNAUTHORIZED, m.to_string());
    let forbidden = |m: &str| (StatusCode::FORBIDDEN, m.to_string());
    let hash = auth::token_hash(tok);
    let (id, v) = app
        .store
        .list("tokens")
        .into_iter()
        .find(|(_, v, _)| v["hash"].as_str().map_or(false, |h| state::ct_eq(h, &hash)))
        .map(|(i, v, _)| (i, v))
        .ok_or_else(|| denied("jeton invalide"))?;
    if v["expires_at"].as_u64().map_or(false, |t| t < now_ms()) {
        return Err(denied("jeton expiré"));
    }
    let ips: Vec<String> = v["ips"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    if !ips.is_empty() {
        let set = ClientSet::parse(&ips);
        if !ip.parse::<std::net::IpAddr>().map_or(false, |a| set.contains(a)) {
            return Err(forbidden("adresse IP non autorisée pour ce jeton"));
        }
    }
    if path.starts_with("/api/tokens") || (path.starts_with("/api/auth/") && path != "/api/auth/me") || path == "/api/cluster" {
        return Err(forbidden("cette route n'est pas accessible avec un jeton"));
    }
    let read_only_post = path == "/api/check" || path == "/api/resolve";
    if unsafe_method && !read_only_post && v["scope"].as_str() != Some("write") {
        return Err(forbidden("jeton en lecture seule"));
    }
    app.token_used.lock().insert(id, (now_ms(), ip.to_string()));
    Ok(v["name"].as_str().unwrap_or("sans nom").to_string())
}

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

async fn login(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    tls_ext: Option<Extension<crate::tls::IsTls>>,
    headers: HeaderMap,
    Json(r): Json<LoginReq>,
) -> Response {
    let ip = client_ip(&app, &peer, &headers);
    if let Some(w) = app.auth.locked(&ip) {
        return too_many(w);
    }
    let node = app.node.lock().clone();
    let pw = r.password.clone();
    let pw_ok = tokio::task::spawn_blocking(move || auth::verify_pw(&node, &pw)).await.unwrap_or(false);
    if pw_ok && r.username == "admin" {
        app.auth.success(&ip);
        // Migration de l'ancien format de hash.
        let migrate = app.node.lock().pw.is_none();
        if migrate {
            let pw = r.password.clone();
            if let Ok(h) = tokio::task::spawn_blocking(move || auth::hash_pw(&pw)).await {
                let mut n = app.node.lock();
                n.pw = Some(h);
                n.pw_hash.clear();
                n.pw_salt.clear();
                drop(n);
                app.save_node();
            }
        }
        let token = app.auth.create_session(&ip);
        app.auth.event(&ip, "login_ok", "");
        let secure = tls_ext.is_some()
            || is_trusted_proxy(&app, &peer)
            && headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .map_or(false, |v| v.eq_ignore_ascii_case("https"));
        let cookie = cookie_value(&token, auth::SESSION_MAX_AGE_S, secure);
        return ([(header::SET_COOKIE, cookie)], Json(json!({"ok": true}))).into_response();
    }
    // Échec : ralentissement, comptage, éventuel blocage.
    tokio::time::sleep(app.auth.tarpit()).await;
    let lock = app.auth.failure(&ip);
    app.auth.event(&ip, "login_fail", "");
    tracing::warn!("échec de connexion depuis {ip}");
    if let Some(d) = lock {
        app.auth.event(&ip, "locked", &format!("bloquée {} s", d.as_secs()));
        tracing::warn!("{ip} bloquée pendant {} s", d.as_secs());
        return too_many(d);
    }
    (StatusCode::UNAUTHORIZED, Json(json!({"error": "Identifiants incorrects"}))).into_response()
}

async fn logout(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap) -> Response {
    if let Some(t) = session_token(&headers) {
        app.auth.revoke(&t);
        app.auth.event(&client_ip(&app, &peer, &headers), "logout", "");
    }
    ([(header::SET_COOKIE, cookie_value("", 0, false))], Json(json!({"ok": true}))).into_response()
}

async fn me(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap) -> Res {
    let ingress = app.cfg.trusted_ip.as_deref() == Some(peer.ip().to_string().as_str());
    let session = session_token(&headers).map_or(false, |t| app.auth.validate(&t));
    Ok(Json(json!({
        "authenticated": ingress || session,
        "ingress": ingress,
        "user": "admin",
        "pw_locked": app.pw_locked,
    })))
}

#[derive(Deserialize)]
struct PwReq {
    current: String,
    new: String,
}

async fn change_password(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(r): Json<PwReq>,
) -> Result<Response, ApiErr> {
    if app.pw_locked {
        return Err(bad("le mot de passe est imposé par la configuration (ATOM_PASSWORD ou option de l'add-on)"));
    }
    let ip = client_ip(&app, &peer, &headers);
    if let Some(w) = app.auth.locked(&ip) {
        return Ok(too_many(w));
    }
    if r.new.chars().count() < 10 {
        return Err(bad("le nouveau mot de passe doit contenir au moins 10 caractères"));
    }
    let node = app.node.lock().clone();
    let cur = r.current.clone();
    let ok = tokio::task::spawn_blocking(move || auth::verify_pw(&node, &cur)).await.unwrap_or(false);
    if !ok {
        app.auth.failure(&ip);
        app.auth.event(&ip, "login_fail", "mot de passe actuel incorrect (changement de mot de passe)");
        return Err(bad("mot de passe actuel incorrect"));
    }
    let new = r.new.clone();
    let h = tokio::task::spawn_blocking(move || auth::hash_pw(&new)).await.map_err(|e| bad(e.to_string()))?;
    {
        let mut n = app.node.lock();
        n.pw = Some(h);
        n.pw_hash.clear();
        n.pw_salt.clear();
    }
    app.save_node();
    app.auth.revoke_others(session_token(&headers).as_deref());
    app.auth.event(&ip, "password_changed", "");
    Ok(Json(json!({"ok": true})).into_response())
}

async fn revoke_others(State(app): State<Arc<App>>, headers: HeaderMap) -> Res {
    app.auth.revoke_others(session_token(&headers).as_deref());
    Ok(Json(json!({"ok": true})))
}

async fn auth_events(State(app): State<Arc<App>>, headers: HeaderMap) -> Res {
    let cur = session_token(&headers);
    Ok(Json(json!({
        "events": app.auth.events(),
        "locked": app.auth.locked_list().into_iter().map(|(ip, s)| json!({"ip": ip, "seconds": s})).collect::<Vec<_>>(),
        "sessions": app.auth.sessions(cur.as_deref()),
    })))
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
        "dns_error": app.dns_error.lock().clone(),
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

async fn put_value(app: &Arc<App>, col: &str, id: &str, body: Value, actor: &str) -> Res {
    check_col(col)?;
    let mut body = body;
    if let Some(o) = body.as_object_mut() {
        o.remove("id");
        o.remove("updated_at");
    }
    let v = model::validate(col, body).map_err(bad)?;
    if col == "rewrites" || col == "records" {
        for (field, target) in [("clients", "clients"), ("groups", "groups")] {
            for sid in v.get(field).and_then(|x| x.as_array()).into_iter().flatten().filter_map(|x| x.as_str()) {
                if app.store.get(target, sid).is_none() {
                    return Err(bad(format!("{} introuvable : {sid}", if field == "clients" { "client" } else { "groupe" })));
                }
            }
        }
    }
    if col == "clients" {
        if let Some(g) = v.get("group").and_then(|x| x.as_str()).filter(|g| !g.is_empty()) {
            if app.store.get("groups", g).is_none() {
                return Err(bad("groupe introuvable"));
            }
        }
    }
    app.store.put_as(col, id, v.clone(), actor);
    if col == "lists" {
        let (a, id) = (app.clone(), id.to_string());
        tokio::spawn(async move {
            let _ = crate::lists::refresh(&a, &id, true).await;
        });
    }
    Ok(Json(json!({"id": id, "value": v})))
}

async fn create(State(app): State<Arc<App>>, Extension(actor): Extension<Actor>, Path(col): Path<String>, Json(body): Json<Value>) -> Res {
    let id = state::random_hex(4);
    put_value(&app, &col, &id, body, &actor.0).await
}

async fn update(State(app): State<Arc<App>>, Extension(actor): Extension<Actor>, Path((col, id)): Path<(String, String)>, Json(body): Json<Value>) -> Res {
    put_value(&app, &col, &id, body, &actor.0).await
}

async fn remove(State(app): State<Arc<App>>, Extension(actor): Extension<Actor>, Path((col, id)): Path<(String, String)>) -> Res {
    check_col(&col)?;
    if col == "settings" {
        return Err(bad("les réglages ne peuvent pas être supprimés"));
    }
    if col == "clients" || col == "groups" {
        strip_scope(&app, &col, &id, &actor.0);
    }
    if col == "zones" {
        if let Some(z) = app.store.get("zones", &id) {
            let zname = z.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            for (rid, rv, _) in app.store.list("records") {
                if rv.get("zone").and_then(|v| v.as_str()) == Some(&zname) {
                    app.store.delete_as("records", &rid, &actor.0);
                }
            }
        }
    }
    app.store.delete_as(&col, &id, &actor.0);
    Ok(Json(json!({"ok": true})))
}

/// Retire un client ou un groupe supprimé des portées. Une configuration qui n'avait que lui
/// pour portée est supprimée, plutôt que de devenir générale par erreur.
fn strip_scope(app: &Arc<App>, kind: &str, id: &str, actor: &str) {
    for col in ["rewrites", "records"] {
        for (oid, mut v, _) in app.store.list(col) {
            let Some(arr) = v.get_mut(kind).and_then(|x| x.as_array_mut()) else { continue };
            let before = arr.len();
            arr.retain(|x| x.as_str() != Some(id));
            if arr.len() == before {
                continue;
            }
            let empty = |f: &str| v.get(f).and_then(|x| x.as_array()).map_or(true, |a| a.is_empty());
            if empty("clients") && empty("groups") {
                app.store.delete_as(col, &oid, actor);
            } else {
                app.store.put_as(col, &oid, v, actor);
            }
        }
    }
    if kind == "groups" {
        for (cid, mut v, _) in app.store.list("clients") {
            if v.get("group").and_then(|x| x.as_str()) == Some(id) {
                v["group"] = json!("");
                app.store.put_as("clients", &cid, v, actor);
            }
        }
    }
}

// ---------- upstreams ----------

#[derive(Deserialize)]
struct ReorderReq {
    ids: Vec<String>,
}

async fn reorder(State(app): State<Arc<App>>, Extension(actor): Extension<Actor>, Json(r): Json<ReorderReq>) -> Res {
    for (i, id) in r.ids.iter().enumerate() {
        let Some(v) = app.store.get("upstreams", id) else { continue };
        let Ok(mut u) = serde_json::from_value::<UpstreamCfg>(v) else { continue };
        let order = (i + 1) as f64;
        if (u.order - order).abs() > f64::EPSILON {
            u.order = order;
            app.store.put_as("upstreams", id, serde_json::to_value(&u).unwrap_or_default(), &actor.0);
        }
    }
    Ok(Json(json!({"ok": true})))
}

async fn upstream_status(State(app): State<Arc<App>>) -> Res {
    let h = app.health.lock().clone();
    Ok(Json(serde_json::to_value(h).unwrap_or_default()))
}

async fn run_probe(app: &Arc<App>, id: &str, cfg: &UpstreamCfg) -> Res {
    let u = upstream::Upstream::new(id, &cfg.name, &cfg.address, &cfg.bootstrap, cfg.domains.clone())
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
    client: Option<String>,
    #[serde(rename = "type")]
    qtype: Option<String>,
}

async fn check(State(app): State<Arc<App>>, Json(r): Json<CheckReq>) -> Res {
    let name = model::norm_domain(&r.domain);
    if name.is_empty() {
        return Err(bad("domaine vide"));
    }
    let eng = app.engine.load_full();
    let q = Query { id: 0, rd: true, name: name.clone(), qtype: dnswire::T_A, qclass: 1, qend: 0, edns_size: None };
    let ident: Identity = r.client.as_deref().and_then(|c| c.trim().parse().ok()).map(|ip| eng.identify(ip)).unwrap_or_default();
    if eng.settings.rewrites_enabled {
        if let Some(rw) = eng.rewrite_lookup(&name, now_ms(), &ident) {
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
    if let Some(z) = eng.zone_answer(&q, &ident) {
        let nx = z.rcode == dnswire::RC_NXDOMAIN;
        return Ok(Json(json!({"result": "zone", "detail": if nx { "NXDOMAIN (zone locale)" } else { "répondu par une zone locale" }})));
    }
    let ip: std::net::IpAddr = r.client.as_deref().and_then(|c| c.trim().parse().ok()).unwrap_or_else(|| "0.0.0.0".parse().unwrap());
    let qtype = r.qtype.as_deref().and_then(dnswire::type_from_name).unwrap_or(dnswire::T_A);
    let fctx = filter::Ctx { ip, client_name: eng.client_name(&ident), qtype };
    match filter::check(&eng.lists, &name, &fctx, &eng.disabled) {
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
    ids: Option<String>,
}

fn ids_set(ids: &Option<String>) -> Option<ClientSet> {
    ids.as_ref()
        .filter(|s| !s.is_empty())
        .map(|s| ClientSet::parse(&s.split(',').map(str::to_string).collect::<Vec<_>>()))
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
        ids: ids_set(&p.ids),
    };
    Ok(Json(serde_json::to_value(app.qlog.query(&f)).unwrap_or_default()))
}

#[derive(Deserialize, Default)]
struct StatsParams {
    node: Option<String>,
    ids: Option<String>,
}

async fn stats(State(app): State<Arc<App>>, QS(p): QS<StatsParams>) -> Res {
    let set = ids_set(&p.ids);
    let s = app.qlog.stats(&p.node.unwrap_or_default(), set.as_ref());
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

fn addr_string(t: u16, rd: &[u8]) -> Option<String> {
    if t == dnswire::T_A && rd.len() == 4 {
        Some(std::net::Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3]).to_string())
    } else if t == dnswire::T_AAAA && rd.len() == 16 {
        let mut b = [0u8; 16];
        b.copy_from_slice(rd);
        Some(std::net::Ipv6Addr::from(b).to_string())
    } else {
        None
    }
}

#[derive(Deserialize, Default)]
struct CacheParams {
    search: Option<String>,
    limit: Option<usize>,
}

async fn cache_list(State(app): State<Arc<App>>, QS(p): QS<CacheParams>) -> Res {
    let now = std::time::Instant::now();
    let search = p.search.unwrap_or_default().to_lowercase();
    let limit = p.limit.unwrap_or(500).clamp(1, 5000);
    let c = app.cache.lock();
    let live: Vec<_> = c.iter().filter(|(_, e)| e.expires > now).collect();
    let total = live.len();
    let mut v: Vec<Value> = live
        .into_iter()
        .filter(|(k, _)| search.is_empty() || k.0.contains(&search))
        .map(|(k, e)| {
            let info = dnswire::response_info(&e.data).unwrap_or_default();
            let answers: Vec<String> = info.addrs.iter().filter_map(|(t, rd, _)| addr_string(*t, rd)).collect();
            json!({"name": k.0, "type": dnswire::type_name(k.1), "ttl": (e.expires - now).as_secs(), "size": e.data.len(), "rcode": info.rcode, "answers": answers})
        })
        .collect();
    drop(c);
    v.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()).then(a["type"].as_str().cmp(&b["type"].as_str())));
    v.truncate(limit);
    Ok(Json(json!({
        "entries": v,
        "total": total,
        "hits": app.cache_hits.load(std::sync::atomic::Ordering::Relaxed),
        "misses": app.cache_misses.load(std::sync::atomic::Ordering::Relaxed),
        "capacity": app.engine.load().settings.cache_size,
        "enabled": app.engine.load().settings.cache_enabled,
    })))
}

#[derive(Deserialize)]
struct CacheKey {
    name: String,
    #[serde(rename = "type")]
    qtype: String,
}

#[derive(Deserialize)]
struct CacheDelete {
    entries: Vec<CacheKey>,
}

async fn cache_delete(State(app): State<Arc<App>>, Json(r): Json<CacheDelete>) -> Res {
    let set: std::collections::HashSet<(String, String)> =
        r.entries.into_iter().map(|k| (k.name.to_lowercase(), k.qtype.to_uppercase())).collect();
    let mut c = app.cache.lock();
    let before = c.len();
    c.retain(|k, _| !set.contains(&(k.0.clone(), dnswire::type_name(k.1))));
    Ok(Json(json!({"deleted": before - c.len()})))
}

async fn cache_flush(State(app): State<Arc<App>>) -> Res {
    let mut c = app.cache.lock();
    let n = c.len();
    c.clear();
    Ok(Json(json!({"ok": true, "deleted": n})))
}

// ---------- clients ----------

async fn clients_list(State(app): State<Arc<App>>) -> Res {
    let seen = app.qlog.clients_summary();
    let groups = app.store.list("groups");
    let cfgs: Vec<(String, ClientCfg)> = app
        .store
        .list("clients")
        .into_iter()
        .filter_map(|(id, v, _)| serde_json::from_value::<ClientCfg>(v).ok().map(|c| (id, c)))
        .collect();
    let sets: Vec<(String, ClientSet)> = cfgs.iter().map(|(id, c)| (id.clone(), ClientSet::parse(&c.ids))).collect();

    #[derive(Default)]
    struct Agg {
        queries: u64,
        blocked: u64,
        last: u64,
        ips: Vec<String>,
    }
    let mut agg: HashMap<String, Agg> = HashMap::new();
    let mut loose: Vec<(String, Agg)> = Vec::new();
    for (ip, n, b, last) in seen {
        let owner = ip
            .parse::<std::net::IpAddr>()
            .ok()
            .and_then(|addr| sets.iter().filter_map(|(id, s)| s.specificity(addr).map(|sp| (sp, id))).max_by_key(|(sp, _)| *sp))
            .map(|(_, id)| id.clone());
        match owner {
            Some(id) => {
                let a = agg.entry(id).or_default();
                a.queries += n;
                a.blocked += b;
                a.last = a.last.max(last);
                a.ips.push(ip);
            }
            None => loose.push((ip.clone(), Agg { queries: n, blocked: b, last, ips: vec![ip] })),
        }
    }
    let mut clients: Vec<Value> = Vec::new();
    for (id, c) in &cfgs {
        let a = agg.remove(id).unwrap_or_default();
        clients.push(json!({
            "id": id, "key": id, "name": c.name, "ids": c.ids, "group": c.group, "notes": c.notes,
            "block_internet": c.block_internet, "block_lan": c.block_lan, "block_until": c.block_until,
            "queries": a.queries, "blocked": a.blocked, "last_seen": a.last, "ips": a.ips,
        }));
    }
    for (ip, a) in loose {
        clients.push(json!({
            "id": null, "key": ip, "name": "", "ids": [ip.clone()], "group": "", "notes": "",
            "block_internet": false, "block_lan": false, "block_until": null,
            "queries": a.queries, "blocked": a.blocked, "last_seen": a.last, "ips": a.ips,
        }));
    }
    clients.sort_by(|a, b| b["last_seen"].as_u64().cmp(&a["last_seen"].as_u64()));
    let group_rows: Vec<Value> = groups
        .into_iter()
        .map(|(id, v, _)| {
            let members: Vec<&Value> = clients.iter().filter(|c| c["group"].as_str() == Some(id.as_str())).collect();
            let q: u64 = members.iter().filter_map(|c| c["queries"].as_u64()).sum();
            let b: u64 = members.iter().filter_map(|c| c["blocked"].as_u64()).sum();
            let mut g = v;
            g["id"] = json!(id);
            g["members"] = json!(members.len());
            g["queries"] = json!(q);
            g["blocked"] = json!(b);
            g
        })
        .collect();
    Ok(Json(json!({"clients": clients, "groups": group_rows})))
}

#[derive(Deserialize)]
struct PauseReq {
    minutes: Option<u64>,
}

async fn pause(State(app): State<Arc<App>>, Extension(actor): Extension<Actor>, Json(r): Json<PauseReq>) -> Res {
    let mut s: Settings = app
        .store
        .get("settings", "main")
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    s.pause_until = r.minutes.filter(|m| *m > 0).map(|m| now_ms() + m * 60_000);
    app.store.put_as("settings", "main", serde_json::to_value(&s).unwrap_or_default(), &actor.0);
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
        "pairing_code": crate::api_tls::pairing_code(&app),
        "cluster_mode": n.tls.cluster_mode,
        "peers": peers,
    })))
}

#[derive(Deserialize)]
struct JoinReq {
    url: String,
    /// Code d'appairage : le jeton du cluster, éventuellement suivi de « . » et de l'empreinte de l'autorité.
    token: String,
    self_url: String,
}

async fn cluster_join(State(app): State<Arc<App>>, Json(r): Json<JoinReq>) -> Res {
    use crate::tls;
    let url = r.url.trim().trim_end_matches('/').to_string();
    let self_url = r.self_url.trim().trim_end_matches('/').to_string();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(bad("l'adresse de l'autre nœud doit commencer par http:// ou https://"));
    }
    if !(self_url.starts_with("http://") || self_url.starts_with("https://")) {
        return Err(bad("l'adresse de ce nœud doit commencer par http:// ou https://"));
    }
    let code = r.token.trim().to_string();
    let (token, code_fp) = match code.split_once('.') {
        Some((t, f)) => (t.to_string(), f.trim().to_ascii_lowercase()),
        None => (code.clone(), String::new()),
    };
    let (id, name) = {
        let n = app.node.lock();
        (n.node_id.clone(), n.name.clone())
    };
    // Appairage : le certificat du serveur n'est pas encore connu, on le vérifie par l'empreinte du code.
    let probe = if url.starts_with("https://") { tls::pairing_client().map_err(|e| bad(e.to_string()))? } else { app.http.clone() };
    let info_resp = probe
        .get(format!("{url}/api/sync/tlsinfo"))
        .bearer_auth(&token)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| bad(format!("connexion impossible : {e}")))?;
    if info_resp.status() == StatusCode::UNAUTHORIZED {
        return Err(bad("code d'appairage refusé"));
    }
    if !info_resp.status().is_success() {
        return Err(bad(format!("l'autre nœud a répondu {}", info_resp.status())));
    }
    let info: Value = info_resp.json().await.map_err(|e| bad(e.to_string()))?;
    let mode = info["mode"].as_str().unwrap_or("off").to_string();
    let remote_fp = info["ca_fingerprint"].as_str().unwrap_or("").to_string();
    let check_fp = |fp: &str| -> Result<(), ApiErr> {
        if code_fp.is_empty() {
            return Err(bad("ce cluster est chiffré : le code d'appairage doit contenir l'empreinte de l'autorité (« jeton.empreinte »), copie-le depuis la page Certificats ou Cluster de l'autre nœud"));
        }
        if fp.is_empty() || !fp.starts_with(&code_fp) {
            return Err(bad("l'empreinte de l'autorité ne correspond pas à celle du code : appairage interrompu"));
        }
        Ok(())
    };
    if mode != "off" && !url.starts_with("https://") {
        return Err(bad("ce cluster est chiffré : l'adresse de l'autre nœud doit commencer par https://"));
    }
    if mode != "off" && !self_url.starts_with("https://") {
        return Err(bad("ce cluster est chiffré : l'adresse de ce nœud doit commencer par https://"));
    }
    let remote_id;
    let remote_name;
    let mut remote_ca = String::new();
    match mode.as_str() {
        "off" => {
            let resp = probe
                .post(format!("{url}/api/sync/hello"))
                .bearer_auth(&token)
                .timeout(std::time::Duration::from_secs(10))
                .json(&json!({"id": id, "name": name, "url": self_url}))
                .send()
                .await
                .map_err(|e| bad(format!("connexion impossible : {e}")))?;
            if !resp.status().is_success() {
                return Err(bad(format!("l'autre nœud a répondu {}", resp.status())));
            }
            let remote: Value = resp.json().await.map_err(|e| bad(e.to_string()))?;
            remote_id = remote["id"].as_str().unwrap_or("").to_string();
            remote_name = remote["name"].as_str().unwrap_or("").to_string();
            // Ce nœud quitte un éventuel chiffrement précédent.
            app.node.lock().tls.cluster_mode = "off".into();
        }
        "ca" => {
            check_fp(&remote_fp)?;
            let mut names = tls::node_names(&app);
            if let Some(h) = tls::url_host(&self_url) {
                names.push(h);
            }
            let (csr, key) = tls::gen_csr(&names, &id).map_err(|e| bad(e.to_string()))?;
            let resp: Value = probe
                .post(format!("{url}/api/sync/enroll"))
                .bearer_auth(&token)
                .timeout(std::time::Duration::from_secs(15))
                .json(&json!({"id": id, "name": name, "url": self_url, "kind": "csr", "csr_pem": csr}))
                .send()
                .await
                .map_err(|e| bad(format!("connexion impossible : {e}")))?
                .json()
                .await
                .map_err(|e| bad(e.to_string()))?;
            let (Some(crt), Some(ca)) = (resp["cert_pem"].as_str(), resp["ca_pem"].as_str()) else {
                return Err(bad(resp["error"].as_str().unwrap_or("réponse d'appairage invalide").to_string()));
            };
            if !tls::fingerprint(ca).starts_with(&code_fp) {
                return Err(bad("l'autorité reçue ne correspond pas à l'empreinte du code : appairage interrompu"));
            }
            tls::certified_key(crt, &key).map_err(|e| bad(e.to_string()))?;
            tls::write(&app, "ca.crt", ca).map_err(|e| bad(e.to_string()))?;
            tls::remove(&app, "ca.key");
            tls::write(&app, "node.crt", crt).map_err(|e| bad(e.to_string()))?;
            tls::write(&app, "node.key", &key).map_err(|e| bad(e.to_string()))?;
            {
                let mut n = app.node.lock();
                n.tls.cluster_mode = "ca".into();
                n.ca_url = url.clone();
            }
            remote_id = resp["id"].as_str().unwrap_or("").to_string();
            remote_name = resp["name"].as_str().unwrap_or("").to_string();
        }
        "selfsigned" => {
            check_fp(&remote_fp)?;
            let mut names = tls::node_names(&app);
            if let Some(h) = tls::url_host(&self_url) {
                names.push(h);
            }
            crate::api_tls::ensure_own_ca(&app, &names).map_err(|e| bad(e.to_string()))?;
            let mine = tls::read(&app, "ca.crt").unwrap_or_default();
            let resp: Value = probe
                .post(format!("{url}/api/sync/enroll"))
                .bearer_auth(&token)
                .timeout(std::time::Duration::from_secs(15))
                .json(&json!({"id": id, "name": name, "url": self_url, "kind": "ca", "ca_pem": mine}))
                .send()
                .await
                .map_err(|e| bad(format!("connexion impossible : {e}")))?
                .json()
                .await
                .map_err(|e| bad(e.to_string()))?;
            let Some(ca) = resp["ca_pem"].as_str() else {
                return Err(bad(resp["error"].as_str().unwrap_or("réponse d'appairage invalide").to_string()));
            };
            if !tls::fingerprint(ca).starts_with(&code_fp) {
                return Err(bad("l'autorité reçue ne correspond pas à l'empreinte du code : appairage interrompu"));
            }
            remote_id = resp["id"].as_str().unwrap_or("").to_string();
            remote_name = resp["name"].as_str().unwrap_or("").to_string();
            tls::write(&app, &format!("peers/{remote_id}.crt"), ca).map_err(|e| bad(e.to_string()))?;
            remote_ca = ca.to_string();
            app.node.lock().tls.cluster_mode = "selfsigned".into();
        }
        "pki" => {
            if app.node.lock().tls.cluster_mode != "pki" {
                return Err(bad("ce cluster utilise une PKI privée : importe d'abord le certificat de ce nœud dans la page Certificats"));
            }
            let client = app.sync_client.load_full();
            let resp = client
                .post(format!("{url}/api/sync/hello"))
                .bearer_auth(&token)
                .timeout(std::time::Duration::from_secs(10))
                .json(&json!({"id": id, "name": name, "url": self_url}))
                .send()
                .await
                .map_err(|e| bad(format!("connexion impossible (vérifie que les certificats sont signés par la même autorité et couvrent l'adresse utilisée) : {e}")))?;
            if !resp.status().is_success() {
                return Err(bad(format!("l'autre nœud a répondu {}", resp.status())));
            }
            let remote: Value = resp.json().await.map_err(|e| bad(e.to_string()))?;
            remote_id = remote["id"].as_str().unwrap_or("").to_string();
            remote_name = remote["name"].as_str().unwrap_or("").to_string();
        }
        other => return Err(bad(format!("mode de chiffrement inconnu : {other}"))),
    }
    if remote_id.is_empty() || remote_id == id {
        return Err(bad("réponse invalide de l'autre nœud"));
    }
    {
        let mut n = app.node.lock();
        n.cluster_token = token;
        n.advertise_url = self_url;
        n.forgotten.retain(|f| f != &remote_id);
        n.peers.retain(|p| p.id != remote_id);
        n.peers.push(Peer { id: remote_id, name: remote_name, url, ca_pem: remote_ca });
    }
    app.save_node();
    tls::refresh_sync_client(&app);
    app.tls_reload.notify_one();
    app.sync_wake.notify_one();
    Ok(Json(json!({"ok": true})))
}

async fn cluster_sync(State(app): State<Arc<App>>) -> Res {
    sync::sync_once(&app).await;
    Ok(Json(json!({"ok": true})))
}

async fn peer_remove(State(app): State<Arc<App>>, Path(id): Path<String>) -> Res {
    {
        let mut n = app.node.lock();
        n.peers.retain(|p| p.id != id);
        if !n.forgotten.contains(&id) {
            n.forgotten.push(id.clone());
        }
    }
    app.store.forget_peer(&id);
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
        n.forgotten.retain(|f| f != &h.id);
        n.peers.retain(|p| p.id != h.id);
        n.peers.push(Peer { id: h.id, name: h.name, url: h.url.trim_end_matches('/').to_string(), ca_pem: String::new() });
    }
    app.save_node();
    app.sync_wake.notify_one();
    Ok(Json(json!({"id": app.node_id(), "name": app.node_name()})))
}

async fn sync_notify(State(app): State<Arc<App>>, _h: HeaderMap) -> Res {
    app.sync_wake.notify_one();
    Ok(Json(json!({"ok": true})))
}
