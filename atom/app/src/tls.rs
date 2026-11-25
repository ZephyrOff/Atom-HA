//! HTTPS pour l'interface web et chiffrement des échanges entre nœuds (mTLS).
//!
//! Trois façons de faire confiance entre nœuds :
//! - `ca` : une autorité de certification propre au cluster (un nœud la détient et signe les autres) ;
//! - `selfsigned` : chaque nœud a sa propre autorité, les nœuds échangent leurs certificats d'autorité ;
//! - `pki` : certificats fournis par l'utilisateur (sa PKI privée).

use crate::state::App;
use anyhow::{anyhow, bail, Result};
use axum::extract::ConnectInfo;
use axum::{Extension, Router};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct TlsSettings {
    pub web_enabled: bool,
    pub web_port: u16,
    /// Nom d'hôte de l'interface (certificat et redirection).
    pub hostname: String,
    pub redirect_http: bool,
    /// off | ca | selfsigned | pki
    pub cluster_mode: String,
    /// Mode utilisé avant la désactivation, pour pouvoir le réactiver sans refaire l'appairage.
    pub previous_mode: String,
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self { web_enabled: false, web_port: 3443, hostname: String::new(), redirect_http: false, cluster_mode: "off".into(), previous_mode: String::new() }
    }
}

/// Marque une requête arrivée par la connexion HTTPS.
#[derive(Clone)]
pub struct IsTls;

/// Certificat client présenté (et vérifié par rustls) par le nœud qui nous appelle.
#[derive(Clone, Debug)]
pub struct PeerCert {
    pub subject: String,
    pub fingerprint: String,
}

pub fn dir(app: &App) -> PathBuf {
    app.cfg.data_dir.join("tls")
}

fn write_secret(path: &std::path::Path, data: &str) -> Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(data.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, data)?;
    Ok(())
}

pub fn read(app: &App, name: &str) -> Option<String> {
    std::fs::read_to_string(dir(app).join(name)).ok().filter(|s| !s.trim().is_empty())
}

pub fn write(app: &App, name: &str, data: &str) -> Result<()> {
    write_secret(&dir(app).join(name), data)
}

pub fn remove(app: &App, name: &str) {
    let _ = std::fs::remove_file(dir(app).join(name));
}

// ---------- génération ----------

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, cn);
    d.push(DnType::OrganizationName, "Atom");
    d
}

fn validity(p: &mut CertificateParams, days: i64) {
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::days(1);
    p.not_after = now + time::Duration::days(days);
}

/// Nouvelle autorité de certification : (certificat PEM, clé PEM).
pub fn gen_ca(cn: &str) -> Result<(String, String)> {
    let key = KeyPair::generate()?;
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    p.distinguished_name = dn(cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    validity(&mut p, 3650);
    let cert = p.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn leaf_params(names: &[String], cn: &str, days: i64) -> Result<CertificateParams> {
    let mut p = CertificateParams::new(names.to_vec())?;
    p.distinguished_name = dn(cn);
    p.is_ca = IsCa::NoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    validity(&mut p, days);
    Ok(p)
}

/// Certificat de nœud signé par une autorité : (certificat PEM, clé PEM).
pub fn issue_leaf(ca_cert_pem: &str, ca_key_pem: &str, names: &[String], cn: &str, days: i64) -> Result<(String, String)> {
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, KeyPair::from_pem(ca_key_pem)?)?;
    let key = KeyPair::generate()?;
    let cert = leaf_params(names, cn, days)?.signed_by(&key, &issuer)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Certificat auto-signé simple (pour l'interface web sans autorité).
pub fn self_signed_leaf(names: &[String], cn: &str, days: i64) -> Result<(String, String)> {
    let key = KeyPair::generate()?;
    let cert = leaf_params(names, cn, days)?.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Demande de signature : (CSR PEM, clé PEM).
pub fn gen_csr(names: &[String], cn: &str) -> Result<(String, String)> {
    let key = KeyPair::generate()?;
    let csr = leaf_params(names, cn, 1)?.serialize_request(&key)?;
    Ok((csr.pem()?, key.serialize_pem()))
}

/// Signe la demande d'un nœud avec la clé de l'autorité.
pub fn sign_csr(ca_cert_pem: &str, ca_key_pem: &str, csr_pem: &str, extra_names: &[String], days: i64) -> Result<String> {
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, KeyPair::from_pem(ca_key_pem)?)?;
    let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
    csr.params.is_ca = IsCa::NoCa;
    csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    validity(&mut csr.params, days);
    for n in extra_names {
        let san = match n.parse::<std::net::IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => match n.clone().try_into() {
                Ok(d) => SanType::DnsName(d),
                Err(_) => continue,
            },
        };
        if !csr.params.subject_alt_names.contains(&san) {
            csr.params.subject_alt_names.push(san);
        }
    }
    Ok(csr.signed_by(&issuer)?.pem())
}

// ---------- lecture ----------

pub fn certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let v: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes()).collect::<Result<_, _>>().map_err(|e| anyhow!("certificat illisible : {e}"))?;
    if v.is_empty() {
        bail!("aucun certificat dans ce texte");
    }
    Ok(v)
}

pub fn key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|e| anyhow!("clé privée illisible : {e}"))
}

pub fn certified_key(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey> {
    let chain = certs_from_pem(cert_pem)?;
    let key = key_from_pem(key_pem)?;
    let signer = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| anyhow!("type de clé non pris en charge : {e}"))?;
    let ck = CertifiedKey::new(chain, signer);
    ck.keys_match().map_err(|_| anyhow!("la clé privée ne correspond pas au certificat"))?;
    Ok(ck)
}

pub fn fingerprint_der(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// Empreinte SHA-256 (hexadécimal) du premier certificat d'un texte PEM.
pub fn fingerprint(pem: &str) -> String {
    certs_from_pem(pem).ok().and_then(|c| c.first().map(|d| fingerprint_der(d))).unwrap_or_default()
}

#[derive(Serialize, Clone, Debug)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub names: Vec<String>,
    /// Parmi les noms, ceux déclarés comme adresses IP (et non comme noms DNS).
    pub ips: Vec<String>,
    pub not_before: u64,
    pub not_after: u64,
    pub fingerprint: String,
    pub is_ca: bool,
}

pub fn cert_info_der(der: &[u8]) -> Result<CertInfo> {
    use x509_parser::prelude::*;
    let (_, c) = parse_x509_certificate(der).map_err(|e| anyhow!("certificat invalide : {e}"))?;
    let mut names = Vec::new();
    let mut ips = Vec::new();
    if let Ok(Some(san)) = c.subject_alternative_name() {
        for g in &san.value.general_names {
            match g {
                GeneralName::DNSName(d) => names.push(d.to_string()),
                GeneralName::IPAddress(b) => {
                    if b.len() == 4 {
                        let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string();
                        ips.push(ip.clone());
                        names.push(ip);
                    } else if b.len() == 16 {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(b);
                        let ip = std::net::Ipv6Addr::from(a).to_string();
                        ips.push(ip.clone());
                        names.push(ip);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(CertInfo {
        subject: c.subject().to_string(),
        issuer: c.issuer().to_string(),
        names,
        ips,
        not_before: (c.validity().not_before.timestamp().max(0) as u64) * 1000,
        not_after: (c.validity().not_after.timestamp().max(0) as u64) * 1000,
        fingerprint: fingerprint_der(der),
        is_ca: c.is_ca(),
    })
}

pub fn cert_info(pem: &str) -> Result<CertInfo> {
    let c = certs_from_pem(pem)?;
    cert_info_der(&c[0])
}

/// Explique en français pourquoi rustls refuse un certificat.
pub fn explain(e: &rustls::Error) -> String {
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            C::UnknownIssuer => "l'autorité fournie n'est pas celle qui a signé ce certificat (ou une autorité intermédiaire manque dans le certificat)".into(),
            C::InvalidPurposeContext { required, presented } => format!("le certificat n'a pas l'usage requis ({required:?}) ; usages présents : {presented:?}. Il faut l'extension « Extended Key Usage » avec serverAuth et clientAuth"),
            C::InvalidPurpose => "le certificat n'autorise pas cet usage : il lui manque l'extension « Extended Key Usage » avec serverAuth et clientAuth".into(),
            C::NotValidForName | C::NotValidForNameContext { .. } => "l'adresse ou le nom utilisé n'est pas dans la liste des noms (SAN) du certificat".into(),
            C::Expired | C::ExpiredContext { .. } => "le certificat est expiré".into(),
            C::NotValidYet | C::NotValidYetContext { .. } => "le certificat n'est pas encore valide (vérifie l'heure du nœud)".into(),
            C::BadSignature => "la signature du certificat est invalide".into(),
            other => format!("{other:?}"),
        },
        other => other.to_string(),
    }
}

/// Vérifie qu'un certificat de nœud fourni par l'utilisateur sera accepté : émis par l'autorité donnée,
/// utilisable comme serveur et comme client, valable pour ses propres noms.
pub fn validate_pki(cert_pem: &str, ca_pem: &str, required_name: Option<&str>) -> Result<()> {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{ServerName, UnixTime};
    let chain = certs_from_pem(cert_pem)?;
    let (end, inter) = chain.split_first().ok_or_else(|| anyhow!("certificat vide"))?;
    let mut roots = RootCertStore::empty();
    for c in certs_from_pem(ca_pem)? {
        roots.add(c).map_err(|e| anyhow!("autorité inutilisable : {e}"))?;
    }
    let roots = Arc::new(roots);
    let now = UnixTime::now();
    let cv = rustls::server::WebPkiClientVerifier::builder_with_provider(roots.clone(), provider())
        .build()
        .map_err(|e| anyhow!("{e}"))?;
    cv.verify_client_cert(end, inter, now).map_err(|e| anyhow!("usage « client » refusé : {}", explain(&e)))?;
    let info = cert_info_der(end)?;
    if info.names.is_empty() {
        bail!("le certificat ne contient aucun nom (SAN) : ajoute l'adresse IP ou le nom du nœud");
    }
    if let Some(n) = required_name {
        if n.parse::<std::net::IpAddr>().is_ok() && !info.ips.iter().any(|x| x == n) {
            if info.names.iter().any(|x| x == n) {
                bail!("« {n} » est déclaré comme nom DNS dans le certificat : une adresse IP doit être déclarée comme « IP Address » dans le SAN (subjectAltName = IP:{n}), sinon elle est refusée");
            }
            bail!("l'adresse annoncée « {n} » n'est pas dans le certificat (noms présents : {})", info.names.join(", "));
        }
        if !info.names.iter().any(|x| x.eq_ignore_ascii_case(n)) {
            bail!("l'adresse annoncée « {n} » n'est pas dans le certificat (noms présents : {})", info.names.join(", "));
        }
    }
    let sv = rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider()).build().map_err(|e| anyhow!("{e}"))?;
    let name = required_name.unwrap_or(&info.names[0]).to_string();
    let sn = ServerName::try_from(name.clone()).map_err(|e| anyhow!("nom invalide : {e}"))?;
    sv.verify_server_cert(end, inter, &sn, &[], now).map_err(|e| anyhow!("usage « serveur » refusé pour {name} : {}", explain(&e)))?;
    Ok(())
}

// ---------- confiance entre nœuds ----------

/// Autorités auxquelles on fait confiance pour authentifier les autres nœuds.
pub fn load_roots(app: &App) -> Option<RootCertStore> {
    let mode = app.node.lock().tls.cluster_mode.clone();
    let mut pems: Vec<String> = Vec::new();
    match mode.as_str() {
        "ca" | "pki" => pems.extend(read(app, "ca.crt")),
        "selfsigned" => {
            pems.extend(read(app, "ca.crt"));
            if let Ok(rd) = std::fs::read_dir(dir(app).join("peers")) {
                for e in rd.flatten() {
                    if let Ok(s) = std::fs::read_to_string(e.path()) {
                        pems.push(s);
                    }
                }
            }
        }
        _ => return None,
    }
    let mut store = RootCertStore::empty();
    for p in pems {
        if let Ok(list) = certs_from_pem(&p) {
            for c in list {
                let _ = store.add(c);
            }
        }
    }
    (!store.is_empty()).then_some(store)
}

/// Noms (adresses) sous lesquels ce nœud doit être joignable.
pub fn node_names(app: &App) -> Vec<String> {
    let n = app.node.lock();
    let mut v: Vec<String> = vec!["localhost".into(), "127.0.0.1".into()];
    if !n.tls.hostname.is_empty() {
        v.push(n.tls.hostname.clone());
    }
    if let Some(h) = url_host(&n.advertise_url) {
        v.push(h);
    }
    if !n.name.is_empty() && n.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        v.push(n.name.clone());
    }
    v.sort();
    v.dedup();
    v
}

pub fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let hostport = rest.split('/').next()?;
    let host = if let Some(r) = hostport.strip_prefix('[') { r.split(']').next()?.to_string() } else { hostport.split(':').next()?.to_string() };
    (!host.is_empty()).then_some(host)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Configuration TLS pour parler aux autres nœuds : on présente notre certificat et on vérifie le leur.
pub fn build_sync_client(app: &App) -> Result<reqwest::Client> {
    let roots = load_roots(app).ok_or_else(|| anyhow!("aucune autorité de confiance"))?;
    let cert = read(app, "node.crt").ok_or_else(|| anyhow!("certificat du nœud absent"))?;
    let key = read(app, "node.key").ok_or_else(|| anyhow!("clé du nœud absente"))?;
    let cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs_from_pem(&cert)?, key_from_pem(&key)?)?;
    Ok(reqwest::Client::builder().use_preconfigured_tls(cfg).user_agent(format!("atom/{}", crate::state::VERSION)).build()?)
}

/// Client qui ne vérifie pas le serveur : réservé à l'appairage, où l'on contrôle l'empreinte à la main.
pub fn pairing_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().danger_accept_invalid_certs(true).user_agent(format!("atom/{}", crate::state::VERSION)).build()?)
}

/// Remet à jour le client utilisé pour la synchronisation selon le mode actuel.
pub fn refresh_sync_client(app: &App) {
    let mode = app.node.lock().tls.cluster_mode.clone();
    if mode == "off" {
        app.sync_client.store(Arc::new(app.http.clone()));
        return;
    }
    match build_sync_client(app) {
        Ok(c) => app.sync_client.store(Arc::new(c)),
        Err(e) => {
            tracing::warn!("client TLS du cluster indisponible : {e}");
            *app.tls_error.lock() = e.to_string();
        }
    }
}

// ---------- serveur HTTPS ----------

#[derive(Debug)]
struct Resolver {
    web: Option<(Arc<CertifiedKey>, Vec<String>)>,
    node: Option<Arc<CertifiedKey>>,
}

fn name_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.to_ascii_lowercase();
    if let Some(suffix) = p.strip_prefix("*.") {
        host.split_once('.').map_or(false, |(_, rest)| rest == suffix)
    } else {
        p == host
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, ch: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let (Some(sni), Some((w, names))) = (ch.server_name().map(|s| s.to_ascii_lowercase()), &self.web) {
            if names.iter().any(|n| name_matches(n, &sni)) {
                return Some(w.clone());
            }
        }
        self.node.clone().or_else(|| self.web.as_ref().map(|w| w.0.clone()))
    }
}

/// Un nom d'hôte ou une adresse est-il couvert par le certificat web ? (sans SNI, on sert le certificat du nœud)
pub fn build_server_config(app: &App) -> Result<Option<rustls::ServerConfig>> {
    let st = app.node.lock().tls.clone();
    let web = match (read(app, "web.crt"), read(app, "web.key")) {
        (Some(c), Some(k)) => {
            let names = cert_info(&c).map(|i| i.names).unwrap_or_default();
            Some((Arc::new(certified_key(&c, &k)?), names.into_iter().map(|n| n.to_ascii_lowercase()).collect::<Vec<_>>()))
        }
        _ => None,
    };
    let node = match (st.cluster_mode.as_str(), read(app, "node.crt"), read(app, "node.key")) {
        ("off", _, _) => None,
        (_, Some(c), Some(k)) => Some(Arc::new(certified_key(&c, &k)?)),
        _ => None,
    };
    if web.is_none() && node.is_none() {
        return Ok(None);
    }
    let resolver = Arc::new(Resolver { web, node });
    let builder = rustls::ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions()?;
    let mut cfg = match load_roots(app) {
        Some(roots) => {
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
                .allow_unauthenticated()
                .build()
                .map_err(|e| anyhow!("vérificateur de certificats clients : {e}"))?;
            builder.with_client_cert_verifier(verifier).with_cert_resolver(resolver)
        }
        None => builder.with_no_client_auth().with_cert_resolver(resolver),
    };
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Some(cfg))
}

fn wanted_port(app: &App, have_config: bool) -> Option<u16> {
    let st = app.node.lock().tls.clone();
    ((st.web_enabled || st.cluster_mode != "off") && have_config).then_some(st.web_port)
}

async fn accept_loop(app: Arc<App>, router: Router, listener: tokio::net::TcpListener) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("accept TLS : {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(cfg) = app.tls_cfg.load_full() else { continue };
        let router = router.clone();
        tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
            let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await else { return };
            let pc = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).and_then(|d| cert_info_der(d).ok()).map(|i| PeerCert { subject: i.subject, fingerprint: i.fingerprint });
            let mut r = router.layer(Extension(ConnectInfo::<SocketAddr>(peer))).layer(Extension(IsTls));
            if let Some(pc) = pc {
                r = r.layer(Extension(pc));
            }
            let io = hyper_util::rt::TokioIo::new(tls);
            let svc = hyper_util::service::TowerToHyperService::new(r);
            let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection_with_upgrades(io, svc).await;
        });
    }
}

/// Gère le serveur HTTPS : le démarre, l'arrête ou le rebranche quand les réglages ou les certificats changent.
pub async fn run(app: Arc<App>, router: Router) {
    let mut current: Option<(u16, tokio::task::JoinHandle<()>)> = None;
    loop {
        let cfg = match build_server_config(&app) {
            Ok(c) => {
                app.tls_error.lock().clear();
                c
            }
            Err(e) => {
                *app.tls_error.lock() = e.to_string();
                None
            }
        };
        let have = cfg.is_some();
        app.tls_cfg.store(cfg.map(Arc::new));
        let want = wanted_port(&app, have);
        match (&current, want) {
            (Some((p, _)), Some(w)) if *p == w => {}
            (cur, Some(port)) => {
                if let Some((_, h)) = cur {
                    h.abort();
                }
                current = None;
                tokio::time::sleep(Duration::from_millis(100)).await;
                match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
                    Ok(l) => {
                        tracing::info!("HTTPS à l'écoute sur le port {port}");
                        *app.tls_listening.lock() = Some(port);
                        current = Some((port, tokio::spawn(accept_loop(app.clone(), router.clone(), l))));
                    }
                    Err(e) => {
                        *app.tls_error.lock() = format!("écoute HTTPS sur le port {port} impossible : {e}");
                        *app.tls_listening.lock() = None;
                    }
                }
            }
            (Some((_, h)), None) => {
                h.abort();
                current = None;
                *app.tls_listening.lock() = None;
            }
            (None, None) => *app.tls_listening.lock() = None,
        }
        tokio::select! {
            _ = app.tls_reload.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(6 * 3600)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_issues_leaf_and_csr_flow() {
        let (ca_crt, ca_key) = gen_ca("Test CA").unwrap();
        let names = vec!["nas.lan".to_string(), "10.0.0.5".to_string()];
        let (crt, key) = issue_leaf(&ca_crt, &ca_key, &names, "n1", 30).unwrap();
        certified_key(&crt, &key).unwrap();
        let info = cert_info(&crt).unwrap();
        assert!(info.names.contains(&"nas.lan".to_string()) && info.names.contains(&"10.0.0.5".to_string()));
        assert!(!info.is_ca);
        assert!(cert_info(&ca_crt).unwrap().is_ca);
        // demande de signature
        let (csr, k2) = gen_csr(&["n2.lan".to_string()], "n2").unwrap();
        let crt2 = sign_csr(&ca_crt, &ca_key, &csr, &["192.168.1.9".to_string()], 30).unwrap();
        certified_key(&crt2, &k2).unwrap();
        let i2 = cert_info(&crt2).unwrap();
        assert!(i2.names.contains(&"n2.lan".to_string()) && i2.names.contains(&"192.168.1.9".to_string()));
        assert_eq!(i2.issuer, cert_info(&ca_crt).unwrap().subject);
    }

    #[test]
    fn pki_validation_explains_problems() {
        let (ca, cak) = gen_ca("Test CA").unwrap();
        let (good, _) = issue_leaf(&ca, &cak, &["192.168.2.113".to_string()], "n", 30).unwrap();
        validate_pki(&good, &ca, Some("192.168.2.113")).unwrap();
        // autre adresse que celle du certificat
        let e = validate_pki(&good, &ca, Some("192.168.2.99")).unwrap_err().to_string();
        assert!(e.contains("192.168.2.99"), "{e}");
        // autre autorité
        let (other, _) = gen_ca("Autre").unwrap();
        let e = validate_pki(&good, &other, None).unwrap_err().to_string();
        assert!(e.contains("autorité"), "{e}");
        // certificat réservé à l'usage serveur : refusé comme certificat client
        let issuer = Issuer::from_ca_cert_pem(&ca, KeyPair::from_pem(&cak).unwrap()).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut p = leaf_params(&["10.0.0.7".to_string()], "srv", 30).unwrap();
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let srv_only = p.signed_by(&key, &issuer).unwrap().pem();
        let e = validate_pki(&srv_only, &ca, None).unwrap_err().to_string();
        assert!(e.contains("client") && e.contains("Extended Key Usage"), "{e}");
    }

    #[test]
    fn ip_declared_as_dns_name_is_explained() {
        let (ca, cak) = gen_ca("Test CA").unwrap();
        let issuer = Issuer::from_ca_cert_pem(&ca, KeyPair::from_pem(&cak).unwrap()).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut p = leaf_params(&[], "n", 30).unwrap();
        p.subject_alt_names = vec![SanType::DnsName("192.168.2.113".try_into().unwrap())];
        let crt = p.signed_by(&key, &issuer).unwrap().pem();
        let e = validate_pki(&crt, &ca, Some("192.168.2.113")).unwrap_err().to_string();
        assert!(e.contains("IP Address"), "{e}");
    }

    #[test]
    fn mismatched_key_is_rejected() {
        let (crt, _) = self_signed_leaf(&["a.lan".to_string()], "a", 10).unwrap();
        let (_, other_key) = self_signed_leaf(&["b.lan".to_string()], "b", 10).unwrap();
        assert!(certified_key(&crt, &other_key).is_err());
    }

    #[test]
    fn host_of_url() {
        assert_eq!(url_host("https://192.168.1.2:3443").as_deref(), Some("192.168.1.2"));
        assert_eq!(url_host("http://atom.lan/x").as_deref(), Some("atom.lan"));
        assert_eq!(url_host("https://[fd00::1]:3443").as_deref(), Some("fd00::1"));
    }

    /// Handshake réel : un serveur exige un certificat client signé par la même autorité.
    #[tokio::test]
    async fn mtls_handshake_with_ca() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_crt, ca_key) = gen_ca("Test CA").unwrap();
        let (s_crt, s_key) = issue_leaf(&ca_crt, &ca_key, &["localhost".to_string()], "server", 30).unwrap();
        let (c_crt, c_key) = issue_leaf(&ca_crt, &ca_key, &["client.lan".to_string()], "client", 30).unwrap();
        let mut roots = RootCertStore::empty();
        for c in certs_from_pem(&ca_crt).unwrap() {
            roots.add(c).unwrap();
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots.clone()), provider()).build().unwrap();
        let server_cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(Resolver { web: None, node: Some(Arc::new(certified_key(&s_crt, &s_key).unwrap())) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acc.accept(tcp).await {
                        let mut b = [0u8; 4];
                        if tls.read_exact(&mut b).await.is_ok() {
                            let _ = tls.write_all(b"pong").await;
                        }
                    }
                });
            }
        });
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        // avec certificat client : accepté
        let good = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(certs_from_pem(&c_crt).unwrap(), key_from_pem(&c_key).unwrap())
            .unwrap();
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(good)).connect(name.clone(), tcp).await.unwrap();
        tls.write_all(b"ping").await.unwrap();
        let mut out = [0u8; 4];
        tls.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"pong");
        // sans certificat client : refusé
        let bad = rustls::ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let res = async {
            let mut tls = tokio_rustls::TlsConnector::from(Arc::new(bad)).connect(name, tcp).await?;
            tls.write_all(b"ping").await?;
            let mut out = [0u8; 4];
            tls.read_exact(&mut out).await?;
            Ok::<_, std::io::Error>(())
        }
        .await;
        assert!(res.is_err(), "un client sans certificat doit être refusé");
    }
}
