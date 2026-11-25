//! API : certificats (interface web et cluster), appairage sécurisé des nœuds.

use crate::api::{bad, ApiErr, Res};
use crate::state::{App, Peer};
use crate::tls;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/tls/status", get(status))
        .route("/api/tls/settings", post(settings))
        .route("/api/tls/web/import", post(web_import))
        .route("/api/tls/web/generate", post(web_generate))
        .route("/api/tls/web/remove", post(web_remove))
        .route("/api/tls/cluster/init-ca", post(cluster_init_ca))
        .route("/api/tls/cluster/selfsigned", post(cluster_selfsigned))
        .route("/api/tls/cluster/pki", post(cluster_pki))
        .route("/api/tls/cluster/off", post(cluster_off))
        .route("/api/tls/cluster/renew", post(cluster_renew))
        .route("/api/tls/ca.crt", get(ca_download))
        .route("/api/sync/tlsinfo", get(sync_tlsinfo))
        .route("/api/sync/enroll", post(sync_enroll))
}

const LEAF_DAYS: i64 = 730;

fn err(e: impl std::fmt::Display) -> ApiErr {
    ApiErr(StatusCode::BAD_REQUEST, e.to_string())
}

fn reload(app: &Arc<App>) {
    app.save_node();
    tls::refresh_sync_client(app);
    app.tls_reload.notify_one();
    app.sync_wake.notify_one();
}

fn info_of(app: &App, name: &str) -> Value {
    match tls::read(app, name).and_then(|p| tls::cert_info(&p).ok()) {
        Some(i) => serde_json::to_value(i).unwrap_or(Value::Null),
        None => Value::Null,
    }
}

/// Code d'appairage : le jeton du cluster, suivi de l'empreinte de l'autorité si on en utilise une.
pub fn pairing_code(app: &App) -> String {
    let (token, mode) = {
        let n = app.node.lock();
        (n.cluster_token.clone(), n.tls.cluster_mode.clone())
    };
    match (mode.as_str(), tls::read(app, "ca.crt")) {
        ("ca" | "selfsigned", Some(ca)) => format!("{token}.{}", &tls::fingerprint(&ca)[..16]),
        _ => token,
    }
}

async fn status(State(app): State<Arc<App>>) -> Res {
    let n = app.node.lock().clone();
    let ca_info = info_of(&app, "ca.crt");
    let peers: Vec<Value> = n.peers.iter().map(|p| json!({"id": p.id, "name": p.name, "url": p.url, "https": p.url.starts_with("https://")})).collect();
    Ok(Json(json!({
        "settings": n.tls,
        "advertise_url": n.advertise_url,
        "listening": *app.tls_listening.lock(),
        "error": app.tls_error.lock().clone(),
        "web": info_of(&app, "web.crt"),
        "node": info_of(&app, "node.crt"),
        "ca": ca_info,
        "ca_has_key": tls::read(&app, "ca.key").is_some(),
        "ca_url": n.ca_url,
        "pairing_code": pairing_code(&app),
        "peers": peers,
        "names": tls::node_names(&app),
    })))
}

#[derive(Deserialize)]
struct SettingsReq {
    web_enabled: bool,
    web_port: u16,
    hostname: String,
    redirect_http: bool,
    advertise_url: Option<String>,
}

async fn settings(State(app): State<Arc<App>>, Json(r): Json<SettingsReq>) -> Res {
    if r.web_port < 1024 && r.web_port != 443 {
        return Err(bad("le port HTTPS doit être 443 ou supérieur à 1024"));
    }
    let host = r.hostname.trim().to_ascii_lowercase();
    if !host.is_empty() && !crate::model::valid_hostname(&host) && host.parse::<std::net::IpAddr>().is_err() {
        return Err(bad("nom d'hôte invalide"));
    }
    if r.redirect_http && tls::read(&app, "web.crt").is_none() {
        return Err(bad("importe ou génère d'abord un certificat pour l'interface"));
    }
    if r.web_enabled && tls::read(&app, "web.crt").is_none() {
        return Err(bad("importe ou génère d'abord un certificat pour l'interface"));
    }
    {
        let mut n = app.node.lock();
        n.tls.web_enabled = r.web_enabled;
        n.tls.web_port = r.web_port;
        n.tls.hostname = host;
        n.tls.redirect_http = r.redirect_http;
        if let Some(u) = r.advertise_url.as_ref().map(|u| u.trim().trim_end_matches('/').to_string()) {
            if !u.is_empty() && !(u.starts_with("http://") || u.starts_with("https://")) {
                return Err(bad("l'adresse annoncée doit commencer par http:// ou https://"));
            }
            n.advertise_url = u;
        }
    }
    reload(&app);
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct PemPair {
    cert_pem: String,
    key_pem: String,
}

async fn web_import(State(app): State<Arc<App>>, Json(r): Json<PemPair>) -> Res {
    tls::certified_key(&r.cert_pem, &r.key_pem).map_err(err)?;
    tls::write(&app, "web.crt", &r.cert_pem).map_err(err)?;
    tls::write(&app, "web.key", &r.key_pem).map_err(err)?;
    reload(&app);
    Ok(Json(json!({"ok": true, "info": info_of(&app, "web.crt")})))
}

#[derive(Deserialize, Default)]
struct GenReq {
    hostname: Option<String>,
}

async fn web_generate(State(app): State<Arc<App>>, Json(r): Json<GenReq>) -> Res {
    if let Some(h) = r.hostname.as_ref().map(|h| h.trim().to_ascii_lowercase()).filter(|h| !h.is_empty()) {
        app.node.lock().tls.hostname = h;
    }
    let names = tls::node_names(&app);
    let cn = app.node.lock().tls.hostname.clone();
    let cn = if cn.is_empty() { app.node_name() } else { cn };
    let (crt, key, signed_by_ca) = match (tls::read(&app, "ca.crt"), tls::read(&app, "ca.key")) {
        (Some(ca), Some(cak)) => {
            let (c, k) = tls::issue_leaf(&ca, &cak, &names, &cn, LEAF_DAYS).map_err(err)?;
            (c, k, true)
        }
        _ => {
            let (c, k) = tls::self_signed_leaf(&names, &cn, 825).map_err(err)?;
            (c, k, false)
        }
    };
    tls::write(&app, "web.crt", &crt).map_err(err)?;
    tls::write(&app, "web.key", &key).map_err(err)?;
    app.node.lock().tls.web_enabled = true;
    reload(&app);
    Ok(Json(json!({"ok": true, "signed_by_ca": signed_by_ca, "info": info_of(&app, "web.crt")})))
}

async fn web_remove(State(app): State<Arc<App>>) -> Res {
    tls::remove(&app, "web.crt");
    tls::remove(&app, "web.key");
    {
        let mut n = app.node.lock();
        n.tls.web_enabled = false;
        n.tls.redirect_http = false;
    }
    reload(&app);
    Ok(Json(json!({"ok": true})))
}

fn need_names(app: &App) -> Result<Vec<String>, ApiErr> {
    let n = app.node.lock();
    let has_real = !n.tls.hostname.is_empty() || !n.advertise_url.is_empty();
    drop(n);
    if !has_real {
        return Err(bad("renseigne d'abord l'adresse de ce nœud (adresse annoncée ou nom d'hôte) : elle est inscrite dans le certificat"));
    }
    Ok(tls::node_names(app))
}

async fn cluster_init_ca(State(app): State<Arc<App>>) -> Res {
    if tls::read(&app, "ca.key").is_some() {
        return Err(bad("une autorité de certification existe déjà sur ce nœud"));
    }
    let names = need_names(&app)?;
    let (ca, cak) = tls::gen_ca("Atom cluster CA").map_err(err)?;
    let (crt, key) = tls::issue_leaf(&ca, &cak, &names, &app.node_name(), LEAF_DAYS).map_err(err)?;
    tls::write(&app, "ca.crt", &ca).map_err(err)?;
    tls::write(&app, "ca.key", &cak).map_err(err)?;
    tls::write(&app, "node.crt", &crt).map_err(err)?;
    tls::write(&app, "node.key", &key).map_err(err)?;
    {
        let mut n = app.node.lock();
        n.tls.cluster_mode = "ca".into();
        n.ca_url = String::new();
    }
    reload(&app);
    Ok(Json(json!({"ok": true, "pairing_code": pairing_code(&app)})))
}

async fn cluster_selfsigned(State(app): State<Arc<App>>) -> Res {
    let names = need_names(&app)?;
    ensure_own_ca(&app, &names).map_err(err)?;
    app.node.lock().tls.cluster_mode = "selfsigned".into();
    reload(&app);
    Ok(Json(json!({"ok": true, "pairing_code": pairing_code(&app)})))
}

/// Crée l'autorité propre à ce nœud et son certificat, si elle n'existe pas encore.
pub fn ensure_own_ca(app: &App, names: &[String]) -> anyhow::Result<()> {
    if tls::read(app, "ca.key").is_some() && tls::read(app, "node.crt").is_some() {
        return Ok(());
    }
    let (ca, cak) = tls::gen_ca(&format!("Atom CA {}", app.node_name()))?;
    let (crt, key) = tls::issue_leaf(&ca, &cak, names, &app.node_name(), LEAF_DAYS)?;
    tls::write(app, "ca.crt", &ca)?;
    tls::write(app, "ca.key", &cak)?;
    tls::write(app, "node.crt", &crt)?;
    tls::write(app, "node.key", &key)?;
    Ok(())
}

#[derive(Deserialize)]
struct PkiReq {
    cert_pem: String,
    key_pem: String,
    ca_pem: String,
}

async fn cluster_pki(State(app): State<Arc<App>>, Json(r): Json<PkiReq>) -> Res {
    tls::certified_key(&r.cert_pem, &r.key_pem).map_err(err)?;
    let cas = tls::certs_from_pem(&r.ca_pem).map_err(err)?;
    if !cas.iter().all(|c| tls::cert_info_der(c).map_or(false, |i| i.is_ca)) {
        return Err(bad("le fichier d'autorités doit contenir uniquement des certificats d'autorité (CA)"));
    }
    tls::write(&app, "node.crt", &r.cert_pem).map_err(err)?;
    tls::write(&app, "node.key", &r.key_pem).map_err(err)?;
    tls::write(&app, "ca.crt", &r.ca_pem).map_err(err)?;
    tls::remove(&app, "ca.key");
    {
        let mut n = app.node.lock();
        n.tls.cluster_mode = "pki".into();
        n.ca_url = String::new();
    }
    reload(&app);
    Ok(Json(json!({"ok": true, "node": info_of(&app, "node.crt")})))
}

async fn cluster_off(State(app): State<Arc<App>>) -> Res {
    app.node.lock().tls.cluster_mode = "off".into();
    reload(&app);
    Ok(Json(json!({"ok": true})))
}

async fn cluster_renew(State(app): State<Arc<App>>) -> Res {
    let mode = app.node.lock().tls.cluster_mode.clone();
    match mode.as_str() {
        "ca" | "selfsigned" if tls::read(&app, "ca.key").is_some() => {
            let (ca, cak) = (tls::read(&app, "ca.crt").unwrap_or_default(), tls::read(&app, "ca.key").unwrap_or_default());
            let (crt, key) = tls::issue_leaf(&ca, &cak, &tls::node_names(&app), &app.node_name(), LEAF_DAYS).map_err(err)?;
            tls::write(&app, "node.crt", &crt).map_err(err)?;
            tls::write(&app, "node.key", &key).map_err(err)?;
        }
        "ca" => {
            let (url, token) = {
                let n = app.node.lock();
                (n.ca_url.clone(), n.cluster_token.clone())
            };
            if url.is_empty() {
                return Err(bad("adresse du nœud qui détient l'autorité inconnue"));
            }
            let (csr, key) = tls::gen_csr(&tls::node_names(&app), &app.node_id()).map_err(err)?;
            let client = app.sync_client.load_full();
            let resp: Value = client
                .post(format!("{url}/api/sync/enroll"))
                .bearer_auth(token)
                .json(&json!({"id": app.node_id(), "name": app.node_name(), "url": app.node.lock().advertise_url.clone(), "kind": "csr", "csr_pem": csr}))
                .send()
                .await
                .map_err(err)?
                .json()
                .await
                .map_err(err)?;
            let crt = resp["cert_pem"].as_str().ok_or_else(|| bad(resp["error"].as_str().unwrap_or("réponse invalide").to_string()))?;
            tls::certified_key(crt, &key).map_err(err)?;
            tls::write(&app, "node.crt", crt).map_err(err)?;
            tls::write(&app, "node.key", &key).map_err(err)?;
        }
        "pki" => return Err(bad("renouvelle le certificat dans ta PKI, puis importe-le à nouveau")),
        _ => return Err(bad("le chiffrement du cluster n'est pas activé")),
    }
    reload(&app);
    Ok(Json(json!({"ok": true, "node": info_of(&app, "node.crt")})))
}

async fn ca_download(State(app): State<Arc<App>>) -> Response {
    match tls::read(&app, "ca.crt") {
        Some(p) => (
            [
                (header::CONTENT_TYPE, "application/x-pem-file".to_string()),
                (header::CONTENT_DISPOSITION, "attachment; filename=\"atom-ca.crt\"".to_string()),
            ],
            p,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "aucune autorité sur ce nœud"}))).into_response(),
    }
}

// ---------- appairage (côté nœud qui accueille) ----------

async fn sync_tlsinfo(State(app): State<Arc<App>>) -> Res {
    let mode = app.node.lock().tls.cluster_mode.clone();
    let fp = tls::read(&app, "ca.crt").map(|c| tls::fingerprint(&c)).unwrap_or_default();
    Ok(Json(json!({"mode": mode, "ca_fingerprint": fp, "id": app.node_id(), "name": app.node_name()})))
}

#[derive(Deserialize)]
struct EnrollReq {
    id: String,
    name: String,
    url: String,
    /// csr | ca
    kind: String,
    csr_pem: Option<String>,
    ca_pem: Option<String>,
}

async fn sync_enroll(State(app): State<Arc<App>>, Json(r): Json<EnrollReq>) -> Res {
    if r.id == app.node_id() {
        return Err(bad("ce nœud est déjà celui-ci"));
    }
    let mode = app.node.lock().tls.cluster_mode.clone();
    let mut out = json!({"id": app.node_id(), "name": app.node_name()});
    let mut peer_ca = String::new();
    match (r.kind.as_str(), mode.as_str()) {
        ("csr", "ca") => {
            let (ca, cak) = match (tls::read(&app, "ca.crt"), tls::read(&app, "ca.key")) {
                (Some(a), Some(b)) => (a, b),
                _ => return Err(bad("ce nœud ne détient pas la clé de l'autorité : adresse-toi au nœud qui l'a créée")),
            };
            let csr = r.csr_pem.as_deref().ok_or_else(|| bad("demande de signature manquante"))?;
            let mut names = Vec::new();
            if let Some(h) = tls::url_host(&r.url) {
                names.push(h);
            }
            let crt = tls::sign_csr(&ca, &cak, csr, &names, LEAF_DAYS).map_err(err)?;
            out["cert_pem"] = json!(crt);
            out["ca_pem"] = json!(ca);
        }
        ("ca", "selfsigned") => {
            let theirs = r.ca_pem.as_deref().ok_or_else(|| bad("certificat d'autorité manquant"))?;
            let list = tls::certs_from_pem(theirs).map_err(err)?;
            if !list.iter().all(|c| tls::cert_info_der(c).map_or(false, |i| i.is_ca)) {
                return Err(bad("ce certificat n'est pas un certificat d'autorité"));
            }
            tls::write(&app, &format!("peers/{}.crt", r.id), theirs).map_err(err)?;
            out["ca_pem"] = json!(tls::read(&app, "ca.crt").unwrap_or_default());
            peer_ca = theirs.to_string();
        }
        _ => return Err(bad(format!("ce nœud est en mode « {mode} » : cet appairage n'est pas possible"))),
    }
    {
        let mut n = app.node.lock();
        n.forgotten.retain(|f| f != &r.id);
        n.peers.retain(|p| p.id != r.id);
        n.peers.push(Peer { id: r.id.clone(), name: r.name.clone(), url: r.url.trim_end_matches('/').to_string(), ca_pem: peer_ca });
    }
    reload(&app);
    Ok(Json(out))
}
