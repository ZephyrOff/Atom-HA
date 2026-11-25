//! État partagé de l'application et fichier propre au nœud.

use crate::engine::Engine;
use crate::filter::ParsedList;
use crate::qlog::QLog;
use crate::store::{now_ms, Store};
use crate::upstream::HealthMap;
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Peer {
    pub id: String,
    pub name: String,
    pub url: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct NodeFile {
    pub node_id: String,
    pub name: String,
    pub cluster_token: String,
    pub pw_salt: String,
    pub pw_hash: String,
    pub advertise_url: String,
    pub peers: Vec<Peer>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct PeerStatus {
    pub ok: bool,
    pub last_ok: u64,
    pub last_error: Option<String>,
    pub latency_ms: u64,
    pub name: String,
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
}

pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    let _ = getrandom::fill(&mut b);
    hex::encode(b)
}

pub fn hash_password(salt: &str, pw: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(pw.as_bytes());
    hex::encode(h.finalize())
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

    pub fn paused(&self) -> bool {
        self.engine.load().settings.pause_until.map_or(false, |t| t > now_ms())
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
    if n.pw_salt.is_empty() {
        n.pw_salt = random_hex(8);
    }
    if let Some(pw) = &cfg.password {
        if !pw.is_empty() {
            n.pw_hash = hash_password(&n.pw_salt, pw);
        }
    }
    if n.pw_hash.is_empty() {
        let pw = random_hex(6);
        n.pw_hash = hash_password(&n.pw_salt, &pw);
        generated = Some(pw);
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&n)?)?;
    Ok((n, generated))
}
