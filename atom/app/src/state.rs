//! État partagé de l'application et fichier propre au nœud.

use crate::engine::Engine;
use crate::filter::ParsedList;
use crate::qlog::QLog;
use crate::store::Store;
use crate::upstream::HealthMap;
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Notify;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
pub struct RunCfg {
    pub data_dir: PathBuf,
    pub dns_listen: String,
    pub http_listen: String,
    pub node_name: Option<String>,
    pub password: Option<String>,
    /// IP à laquelle on fait confiance sans mot de passe (ingress Home Assistant).
    pub trusted_ip: Option<String>,
    pub advertise_url: Option<String>,
    pub log_retention: usize,
    /// IP de reverse proxies dont on accepte l'en-tête X-Forwarded-For.
    pub trusted_proxies: Vec<String>,
    /// Origines supplémentaires acceptées pour les requêtes de l'interface (ex. https://atom.exemple.fr).
    pub allowed_origins: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Peer {
    pub id: String,
    pub name: String,
    pub url: String,
    /// Certificat d'autorité du nœud (mode « auto-signé »), transmis aux autres nœuds.
    #[serde(default)]
    pub ca_pem: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct NodeFile {
    pub node_id: String,
    pub name: String,
    pub cluster_token: String,
    /// Hash Argon2id du mot de passe.
    pub pw: Option<crate::auth::PwHash>,
    /// Ancien format (SHA-256 salé), migré à la première connexion.
    pub pw_salt: String,
    pub pw_hash: String,
    /// Mot de passe d'un second accès, en lecture seule (propre à ce nœud).
    pub ro_pw: Option<crate::auth::PwHash>,
    pub advertise_url: String,
    pub peers: Vec<Peer>,
    /// Nœuds retirés à la main : la propagation automatique ne les rajoute pas.
    pub forgotten: Vec<String>,
    /// Réglages HTTPS et chiffrement du cluster (propres à ce nœud).
    pub tls: crate::tls::TlsSettings,
    /// Adresse du nœud qui détient l'autorité du cluster (pour renouveler le certificat).
    pub ca_url: String,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct PeerStatus {
    pub ok: bool,
    pub last_ok: u64,
    pub last_error: Option<String>,
    pub latency_ms: u64,
    pub name: String,
    pub version: String,
    /// Écart d'horloge estimé avec ce nœud (positif = son horloge avance).
    pub skew_ms: i64,
    pub cert_expires: Option<u64>,
    pub dns_ok: Option<bool>,
    /// Nombre de modifications de configuration que ce nœud n'a pas encore reçues de nous.
    pub behind_ops: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ListMeta {
    pub updated_at: u64,
    pub etag: Option<String>,
    pub rules: usize,
    pub unsupported: usize,
    pub error: Option<String>,
    pub last_attempt: u64,
}

pub struct CacheEntry {
    pub data: Vec<u8>,
    pub expires: Instant,
}

pub struct App {
    pub cfg: RunCfg,
    pub node: Mutex<NodeFile>,
    pub store: Arc<Store>,
    pub qlog: Arc<QLog>,
    pub engine: ArcSwap<Engine>,
    pub cache: Mutex<HashMap<(String, u16, u16), CacheEntry>>,
    pub health: HealthMap,
    pub lists_meta: Mutex<HashMap<String, ListMeta>>,
    pub parse_cache: Mutex<HashMap<String, (String, Arc<ParsedList>)>>,
    pub rebuild: Notify,
    pub sync_wake: Notify,
    pub peer_status: Mutex<HashMap<String, PeerStatus>>,
    pub started: Instant,
    pub http: reqwest::Client,
    pub dns_ok: std::sync::atomic::AtomicBool,
    pub auth: crate::auth::Auth,
    /// Dernière erreur d'écoute du serveur DNS (port occupé, droits manquants…).
    pub dns_error: Mutex<String>,
    /// Dernière utilisation de chaque jeton d'API : (date, adresse).
    pub token_used: Mutex<HashMap<String, (u64, String)>>,
    pub tls_reload: Notify,
    pub tls_cfg: arc_swap::ArcSwapOption<rustls::ServerConfig>,
    pub tls_error: Mutex<String>,
    pub tls_listening: Mutex<Option<u16>>,
    /// Client HTTP utilisé pour parler aux autres nœuds (mTLS quand il est activé).
    pub sync_client: ArcSwap<reqwest::Client>,
    pub cache_hits: std::sync::atomic::AtomicU64,
    pub cache_misses: std::sync::atomic::AtomicU64,
    /// Mot de passe imposé par la configuration (non modifiable dans l'interface).
    pub pw_locked: bool,
    /// Dernières opérations automatiques sur les certificats : (date, message).
    pub cert_log: Mutex<Vec<(u64, String)>>,
}

pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    let _ = getrandom::fill(&mut b);
    hex::encode(b)
}

pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl App {
    pub fn node_id(&self) -> String {
        self.node.lock().node_id.clone()
    }

    pub fn node_name(&self) -> String {
        self.node.lock().name.clone()
    }

    pub fn save_node(&self) {
        let n = self.node.lock().clone();
        let path = self.cfg.data_dir.join("node.json");
        if let Ok(data) = serde_json::to_vec_pretty(&n) {
            let _ = std::fs::write(path, data);
        }
    }

    pub fn save_lists_meta(&self) {
        let m = self.lists_meta.lock().clone();
        let dir = self.cfg.data_dir.join("lists");
        let _ = std::fs::create_dir_all(&dir);
        if let Ok(data) = serde_json::to_vec(&m) {
            let _ = std::fs::write(dir.join("meta.json"), data);
        }
    }
}

/// Charge ou crée le fichier du nœud. Retourne aussi le mot de passe généré, le cas échéant.
pub fn load_node(cfg: &RunCfg) -> anyhow::Result<(NodeFile, Option<String>)> {
    let path = cfg.data_dir.join("node.json");
    let mut n: NodeFile = match std::fs::read(&path) {
        Ok(d) => serde_json::from_slice(&d)?,
        Err(_) => NodeFile::default(),
    };
    let mut generated = None;
    if n.node_id.is_empty() {
        n.node_id = random_hex(6);
    }
    if n.name.is_empty() {
        n.name = format!("atom-{}", &n.node_id[..4]);
    }
    if let Some(name) = &cfg.node_name {
        if !name.is_empty() {
            n.name = name.clone();
        }
    }
    if n.cluster_token.is_empty() {
        n.cluster_token = random_hex(16);
    }
    if let Some(u) = &cfg.advertise_url {
        n.advertise_url = u.clone();
    }
    if let Some(pw) = cfg.password.as_ref().filter(|p| !p.is_empty()) {
        n.pw = Some(crate::auth::hash_pw(pw));
        n.pw_hash.clear();
        n.pw_salt.clear();
    } else if n.pw.is_none() && n.pw_hash.is_empty() {
        let pw = random_hex(8);
        n.pw = Some(crate::auth::hash_pw(&pw));
        generated = Some(pw);
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&n)?)?;
    Ok((n, generated))
}
