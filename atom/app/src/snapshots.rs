//! Versions de la configuration : instantanés complets, automatiques ou manuels.

use crate::state::{random_hex, App};
use crate::store::now_ms;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const AUTO_KEEP: usize = 30;
const MANUAL_KEEP: usize = 100;
const AUTO_MIN_INTERVAL_MS: u64 = 3_600_000;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SnapshotMeta {
    pub id: String,
    pub ts: u64,
    pub label: String,
    pub auto: bool,
    pub objects: usize,
    pub hash: String,
}

fn dir(app: &App) -> PathBuf {
    app.cfg.data_dir.join("snapshots")
}

fn read_index(app: &App) -> Vec<SnapshotMeta> {
    std::fs::read(dir(app).join("index.json"))
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_default()
}

fn write_index(app: &App, idx: &[SnapshotMeta]) {
    let _ = std::fs::create_dir_all(dir(app));
    if let Ok(d) = serde_json::to_vec(idx) {
        let _ = std::fs::write(dir(app).join("index.json"), d);
    }
}

pub fn list(app: &App) -> Vec<SnapshotMeta> {
    let mut v = read_index(app);
    v.sort_by(|a, b| b.ts.cmp(&a.ts));
    v
}

pub type Objects = Vec<(String, String, Value)>;

pub fn load(app: &App, id: &str) -> Option<Objects> {
    if !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let d = std::fs::read(dir(app).join(format!("{id}.json"))).ok()?;
    serde_json::from_slice(&d).ok()
}

/// Prend un instantané de la configuration actuelle. Un instantané automatique identique au précédent est ignoré.
pub fn take(app: &App, label: &str, auto: bool) -> Option<SnapshotMeta> {
    let objs = app.store.export();
    let data = serde_json::to_vec(&objs).ok()?;
    let hash = hex::encode(Sha256::digest(&data));
    let mut idx = read_index(app);
    if auto && idx.iter().max_by_key(|m| m.ts).map_or(false, |m| m.hash == hash) {
        return None;
    }
    let id = random_hex(6);
    let _ = std::fs::create_dir_all(dir(app));
    std::fs::write(dir(app).join(format!("{id}.json")), &data).ok()?;
    let meta = SnapshotMeta { id, ts: now_ms(), label: label.to_string(), auto, objects: objs.len(), hash };
    idx.push(meta.clone());
    // Rotation : on garde les derniers instantanés de chaque sorte.
    for (is_auto, keep) in [(true, AUTO_KEEP), (false, MANUAL_KEEP)] {
        let mut group: Vec<SnapshotMeta> = idx.iter().filter(|m| m.auto == is_auto).cloned().collect();
        group.sort_by(|a, b| b.ts.cmp(&a.ts));
        for old in group.into_iter().skip(keep) {
            let _ = std::fs::remove_file(dir(app).join(format!("{}.json", old.id)));
            idx.retain(|m| m.id != old.id);
        }
    }
    write_index(app, &idx);
    Some(meta)
}

pub fn delete(app: &App, id: &str) -> bool {
    let mut idx = read_index(app);
    let before = idx.len();
    idx.retain(|m| m.id != id);
    if idx.len() == before || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let _ = std::fs::remove_file(dir(app).join(format!("{id}.json")));
    write_index(app, &idx);
    true
}

/// Différences entre un instantané et la configuration actuelle.
pub fn diff(app: &App, target: &Objects) -> Vec<Value> {
    let current = app.store.export();
    let key = |c: &str, i: &str| format!("{c}/{i}");
    let cur: std::collections::HashMap<String, &Value> = current.iter().map(|(c, i, v)| (key(c, i), v)).collect();
    let tgt: std::collections::HashMap<String, &Value> = target.iter().map(|(c, i, v)| (key(c, i), v)).collect();
    let mut out = Vec::new();
    for (c, i, v) in target {
        match cur.get(&key(c, i)) {
            None => out.push(serde_json::json!({"col": c, "id": i, "change": "add", "summary": crate::store::summarize(c, v)})),
            Some(now) if *now != v => out.push(serde_json::json!({"col": c, "id": i, "change": "modify", "summary": crate::store::summarize(c, v)})),
            _ => {}
        }
    }
    for (c, i, v) in &current {
        if !tgt.contains_key(&key(c, i)) {
            out.push(serde_json::json!({"col": c, "id": i, "change": "remove", "summary": crate::store::summarize(c, v)}));
        }
    }
    out
}

/// Tâche de fond : un instantané automatique si la configuration a changé, au plus une fois par heure.
pub async fn run(app: Arc<App>) {
    let mut rx = app.store.version.subscribe();
    let mut last_taken = 0u64;
    loop {
        tokio::time::sleep(Duration::from_secs(600)).await;
        if rx.has_changed().unwrap_or(false) {
            let now = now_ms();
            if now.saturating_sub(last_taken) >= AUTO_MIN_INTERVAL_MS {
                rx.borrow_and_update();
                let a = app.clone();
                if tokio::task::spawn_blocking(move || take(&a, "Automatique", true)).await.ok().flatten().is_some() {
                    last_taken = now;
                }
            }
        }
    }
}
