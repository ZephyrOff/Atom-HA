//! Magasin d'objets répliqué.
//!
//! Chaque objet (collection + id) porte une horloge logique hybride (HLC).
//! En cas de conflit, la valeur avec la plus grande HLC gagne, objet par objet.
//! Un vecteur de versions (origine -> dernier numéro de séquence) permet à un pair
//! de ne demander que ce qui lui manque. Chaque écriture mémorise aussi ce que son
//! auteur avait déjà vu (`seen`), ce qui permet de détecter les modifications concurrentes.
//! Le magasin tient l'historique des modifications et la liste des conflits.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use tokio::sync::watch;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Collections qui ne sont jamais sauvegardées ni restaurées (secrets).
pub const EXCLUDED_FROM_BACKUP: &[&str] = &["tokens"];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Hlc {
    pub wall: u64,
    pub ctr: u32,
    pub node: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Obj {
    pub col: String,
    pub id: String,
    /// `None` = suppression (tombstone).
    pub val: Option<Value>,
    pub hlc: Hlc,
    pub origin: String,
    pub seq: u64,
    /// Vecteur de versions de l'auteur au moment de l'écriture.
    #[serde(default)]
    pub seen: HashMap<String, u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub ts: u64,
    /// Nœud d'origine de la modification.
    pub node: String,
    /// Qui l'a faite : « admin », nom d'un jeton, « système »…
    pub actor: String,
    /// local | remote
    pub source: String,
    pub col: String,
    pub id: String,
    /// create | update | delete
    pub action: String,
    pub summary: String,
    pub before: Option<Value>,
    pub after: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictSide {
    pub node: String,
    pub val: Option<Value>,
    pub ts: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Conflict {
    pub cid: String,
    pub ts: u64,
    pub col: String,
    pub id: String,
    pub summary: String,
    pub winner: ConflictSide,
    pub loser: ConflictSide,
    pub resolved: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct Snapshot {
    node: String,
    seq: u64,
    last_wall: u64,
    last_ctr: u32,
    objs: Vec<Obj>,
    vv: HashMap<String, u64>,
}

struct Inner {
    node: String,
    last_wall: u64,
    last_ctr: u32,
    seq: u64,
    objs: HashMap<String, Obj>,
    vv: HashMap<String, u64>,
}

impl Inner {
    fn tick(&mut self) -> Hlc {
        let now = now_ms();
        let wall = now.max(self.last_wall);
        let ctr = if wall == self.last_wall { self.last_ctr + 1 } else { 0 };
        self.last_wall = wall;
        self.last_ctr = ctr;
        Hlc { wall, ctr, node: self.node.clone() }
    }
    fn observe(&mut self, h: &Hlc) {
        if h.wall > self.last_wall {
            self.last_wall = h.wall;
            self.last_ctr = h.ctr;
        } else if h.wall == self.last_wall {
            self.last_ctr = self.last_ctr.max(h.ctr);
        }
    }
}

fn key(col: &str, id: &str) -> String {
    format!("{col}/{id}")
}

const HISTORY_MAX: usize = 3000;
const CONFLICTS_MAX: usize = 200;
/// Taille maximale d'une valeur conservée dans l'historique.
const HISTORY_VALUE_MAX: usize = 32 * 1024;

pub fn summarize(col: &str, v: &Value) -> String {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    match col {
        "rewrites" => format!("{} → {}", s("domain"), s("answer")),
        "records" => format!("{} {} {} ({})", s("name"), s("type"), s("value"), s("zone")),
        "zones" | "lists" | "clients" | "groups" | "tokens" => s("name"),
        "upstreams" => format!("{} ({})", s("name"), s("address")),
        "rules" => "règles personnalisées".into(),
        "settings" => "réglages DNS".into(),
        _ => String::new(),
    }
}

fn shrink(col: &str, v: &Option<Value>) -> Option<Value> {
    if EXCLUDED_FROM_BACKUP.contains(&col) {
        return None;
    }
    v.as_ref().filter(|x| x.to_string().len() <= HISTORY_VALUE_MAX).cloned()
}

pub struct Store {
    inner: Mutex<Inner>,
    path: PathBuf,
    history: Mutex<VecDeque<HistoryEntry>>,
    conflicts: Mutex<Vec<Conflict>>,
    peer_vv: Mutex<HashMap<String, HashMap<String, u64>>>,
    history_dirty: Mutex<bool>,
    /// Incrémenté à chaque changement (local ou distant).
    pub version: watch::Sender<u64>,
    /// Incrémenté à chaque changement local seulement.
    pub local_version: watch::Sender<u64>,
}

impl Store {
    pub fn open(path: PathBuf, node: &str) -> anyhow::Result<Self> {
        let mut inner = Inner {
            node: node.to_string(),
            last_wall: 0,
            last_ctr: 0,
            seq: 0,
            objs: HashMap::new(),
            vv: HashMap::new(),
        };
        if let Ok(data) = std::fs::read(&path) {
            let snap: Snapshot = serde_json::from_slice(&data)?;
            inner.seq = snap.seq;
            inner.last_wall = snap.last_wall;
            inner.last_ctr = snap.last_ctr;
            inner.vv = snap.vv;
            for o in snap.objs {
                inner.objs.insert(key(&o.col, &o.id), o);
            }
        }
        let side = |name: &str| path.with_file_name(name);
        let history: VecDeque<HistoryEntry> = std::fs::read(side("history.json"))
            .ok()
            .and_then(|d| serde_json::from_slice(&d).ok())
            .unwrap_or_default();
        let conflicts: Vec<Conflict> = std::fs::read(side("conflicts.json"))
            .ok()
            .and_then(|d| serde_json::from_slice(&d).ok())
            .unwrap_or_default();
        Ok(Self {
            inner: Mutex::new(inner),
            path,
            history: Mutex::new(history),
            conflicts: Mutex::new(conflicts),
            peer_vv: Mutex::new(HashMap::new()),
            history_dirty: Mutex::new(false),
            version: watch::channel(0).0,
            local_version: watch::channel(0).0,
        })
    }

    /// Valeur par défaut, écrasée par n'importe quelle vraie écriture.
    pub fn seed(&self, col: &str, id: &str, val: Value) {
        let mut g = self.inner.lock();
        let k = key(col, id);
        g.objs.entry(k).or_insert_with(|| Obj {
            col: col.into(),
            id: id.into(),
            val: Some(val),
            hlc: Hlc { wall: 0, ctr: 0, node: "seed".into() },
            origin: "seed".into(),
            seq: 0,
            seen: HashMap::new(),
        });
    }

    #[cfg(test)]
    pub fn put(&self, col: &str, id: &str, val: Value) {
        self.write(col, id, Some(val), "système");
    }

    pub fn put_as(&self, col: &str, id: &str, val: Value, actor: &str) {
        self.write(col, id, Some(val), actor);
    }

    #[cfg(test)]
    pub fn delete(&self, col: &str, id: &str) {
        self.write(col, id, None, "système");
    }

    pub fn delete_as(&self, col: &str, id: &str, actor: &str) {
        self.write(col, id, None, actor);
    }

    fn write(&self, col: &str, id: &str, val: Option<Value>, actor: &str) {
        let node;
        let before;
        {
            let mut g = self.inner.lock();
            before = g.objs.get(&key(col, id)).and_then(|o| o.val.clone());
            // Une écriture sans effet ne produit ni version, ni historique, ni synchro.
            if before == val {
                return;
            }
            let hlc = g.tick();
            g.seq += 1;
            let seq = g.seq;
            node = g.node.clone();
            g.vv.insert(node.clone(), seq);
            let seen = g.vv.clone();
            g.objs.insert(
                key(col, id),
                Obj { col: col.into(), id: id.into(), val: val.clone(), hlc, origin: node.clone(), seq, seen },
            );
        }
        self.record(HistoryEntry {
            ts: now_ms(),
            node,
            actor: actor.into(),
            source: "local".into(),
            col: col.into(),
            id: id.into(),
            action: match (&before, &val) {
                (_, None) => "delete",
                (None, _) => "create",
                _ => "update",
            }
            .into(),
            summary: summarize(col, val.as_ref().or(before.as_ref()).unwrap_or(&Value::Null)),
            before: shrink(col, &before),
            after: shrink(col, &val),
        });
        self.bump(true);
    }

    fn record(&self, e: HistoryEntry) {
        let mut h = self.history.lock();
        h.push_front(e);
        h.truncate(HISTORY_MAX);
        *self.history_dirty.lock() = true;
    }

    fn bump(&self, local: bool) {
        self.version.send_modify(|v| *v += 1);
        if local {
            self.local_version.send_modify(|v| *v += 1);
        }
    }

    pub fn get(&self, col: &str, id: &str) -> Option<Value> {
        self.inner.lock().objs.get(&key(col, id)).and_then(|o| o.val.clone())
    }

    /// Objets vivants d'une collection : (id, valeur, HLC).
    pub fn list(&self, col: &str) -> Vec<(String, Value, Hlc)> {
        let g = self.inner.lock();
        let mut v: Vec<_> = g
            .objs
            .values()
            .filter(|o| o.col == col)
            .filter_map(|o| o.val.clone().map(|val| (o.id.clone(), val, o.hlc.clone())))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Tous les objets vivants hors collections secrètes : (collection, id, valeur).
    pub fn export(&self) -> Vec<(String, String, Value)> {
        let g = self.inner.lock();
        let mut v: Vec<_> = g
            .objs
            .values()
            .filter(|o| !EXCLUDED_FROM_BACKUP.contains(&o.col.as_str()))
            .filter_map(|o| o.val.clone().map(|val| (o.col.clone(), o.id.clone(), val)))
            .collect();
        v.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        v
    }

    /// Ramène la configuration à l'état décrit (suppression de ce qui n'y figure pas si `replace`).
    /// Retourne (écrits, supprimés).
    pub fn restore(&self, target: &[(String, String, Value)], replace: bool, actor: &str) -> (usize, usize) {
        let current = self.export();
        let want: HashMap<String, &Value> = target.iter().map(|(c, i, v)| (key(c, i), v)).collect();
        let (mut put, mut del) = (0, 0);
        if replace {
            for (c, i, _) in &current {
                if !want.contains_key(&key(c, i)) {
                    self.delete_as(c, i, actor);
                    del += 1;
                }
            }
        }
        for (c, i, v) in target {
            if EXCLUDED_FROM_BACKUP.contains(&c.as_str()) {
                continue;
            }
            if self.get(c, i).as_ref() != Some(v) {
                self.put_as(c, i, v.clone(), actor);
                put += 1;
            }
        }
        (put, del)
    }

    pub fn vv(&self) -> HashMap<String, u64> {
        self.inner.lock().vv.clone()
    }

    /// Objets que le pair (décrit par `vv`) ne connaît pas encore.
    pub fn pull(&self, vv: &HashMap<String, u64>) -> Vec<Obj> {
        let g = self.inner.lock();
        let mut out: Vec<Obj> = g
            .objs
            .values()
            .filter(|o| o.seq > vv.get(&o.origin).copied().unwrap_or(0))
            .cloned()
            .collect();
        out.sort_by(|a, b| (&a.origin, a.seq).cmp(&(&b.origin, b.seq)));
        out
    }

    /// Mémorise ce qu'un pair a déjà reçu (sert au nettoyage des suppressions).
    pub fn note_peer_vv(&self, peer: &str, vv: HashMap<String, u64>) {
        self.peer_vv.lock().insert(peer.to_string(), vv);
    }

    pub fn forget_peer(&self, peer: &str) {
        self.peer_vv.lock().remove(peer);
    }

    /// Applique des objets reçus d'un pair. Retourne vrai si l'état a changé.
    pub fn apply_remote(&self, objs: Vec<Obj>) -> bool {
        let mut changed = false;
        let mut hist: Vec<HistoryEntry> = Vec::new();
        let mut confl: Vec<Conflict> = Vec::new();
        {
            let mut g = self.inner.lock();
            for o in objs {
                if o.origin == g.node {
                    continue;
                }
                g.observe(&o.hlc);
                let e = g.vv.entry(o.origin.clone()).or_insert(0);
                if o.seq > *e {
                    *e = o.seq;
                }
                let k = key(&o.col, &o.id);
                let cur = g.objs.get(&k);
                let newer = match cur {
                    Some(c) => o.hlc > c.hlc,
                    None => true,
                };
                // Modification concurrente : ni l'une ni l'autre n'avait vu l'autre.
                if let Some(c) = cur {
                    let concurrent = c.origin != "seed"
                        && c.origin != o.origin
                        && !o.seen.is_empty()
                        && !c.seen.is_empty()
                        && o.seen.get(&c.origin).copied().unwrap_or(0) < c.seq
                        && c.seen.get(&o.origin).copied().unwrap_or(0) < o.seq
                        && c.val != o.val;
                    if concurrent {
                        let (win, lose) = if newer { (&o, c) } else { (c, &o) };
                        confl.push(Conflict {
                            cid: crate::state::random_hex(6),
                            ts: now_ms(),
                            col: o.col.clone(),
                            id: o.id.clone(),
                            summary: summarize(&o.col, o.val.as_ref().or(c.val.as_ref()).unwrap_or(&Value::Null)),
                            winner: ConflictSide { node: win.origin.clone(), val: win.val.clone(), ts: win.hlc.wall },
                            loser: ConflictSide { node: lose.origin.clone(), val: lose.val.clone(), ts: lose.hlc.wall },
                            resolved: false,
                        });
                    }
                }
                if newer {
                    let before = cur.and_then(|c| c.val.clone());
                    if before != o.val {
                        hist.push(HistoryEntry {
                            ts: now_ms(),
                            node: o.origin.clone(),
                            actor: o.origin.clone(),
                            source: "remote".into(),
                            col: o.col.clone(),
                            id: o.id.clone(),
                            action: match (&before, &o.val) {
                                (_, None) => "delete",
                                (None, _) => "create",
                                _ => "update",
                            }
                            .into(),
                            summary: summarize(&o.col, o.val.as_ref().or(before.as_ref()).unwrap_or(&Value::Null)),
                            before: shrink(&o.col, &before),
                            after: shrink(&o.col, &o.val),
                        });
                    }
                    g.objs.insert(k, o);
                    changed = true;
                }
            }
        }
        for h in hist.into_iter().rev() {
            self.record(h);
        }
        if !confl.is_empty() {
            let mut c = self.conflicts.lock();
            for x in confl {
                c.insert(0, x);
            }
            c.truncate(CONFLICTS_MAX);
            *self.history_dirty.lock() = true;
        }
        if changed {
            self.bump(false);
        }
        changed
    }

    // ----- historique -----

    pub fn history(&self, limit: usize, col: &str, search: &str) -> Vec<HistoryEntry> {
        let s = search.to_lowercase();
        self.history
            .lock()
            .iter()
            .filter(|e| col.is_empty() || e.col == col)
            .filter(|e| s.is_empty() || format!("{} {} {}", e.summary, e.actor, e.id).to_lowercase().contains(&s))
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn history_entry(&self, ts: u64, col: &str, id: &str) -> Option<HistoryEntry> {
        self.history.lock().iter().find(|e| e.ts == ts && e.col == col && e.id == id).cloned()
    }

    // ----- conflits -----

    pub fn conflicts(&self) -> Vec<Conflict> {
        self.conflicts.lock().clone()
    }

    pub fn resolve_conflict(&self, cid: &str) -> Option<Conflict> {
        let mut c = self.conflicts.lock();
        let x = c.iter_mut().find(|x| x.cid == cid)?;
        x.resolved = true;
        let out = x.clone();
        *self.history_dirty.lock() = true;
        Some(out)
    }

    pub fn clear_resolved_conflicts(&self) {
        self.conflicts.lock().retain(|c| !c.resolved);
        *self.history_dirty.lock() = true;
    }

    // ----- nettoyage des suppressions -----

    /// Supprime les marqueurs de suppression assez anciens que tous les pairs connus ont déjà reçus.
    pub fn compact(&self, min_age_ms: u64, peers: &[String]) -> usize {
        let now = now_ms();
        let pv = self.peer_vv.lock();
        let mut g = self.inner.lock();
        let before = g.objs.len();
        g.objs.retain(|_, o| {
            if o.val.is_some() || o.origin == "seed" || now.saturating_sub(o.hlc.wall) < min_age_ms {
                return true;
            }
            let all_have = peers.iter().all(|p| pv.get(p).map_or(false, |vv| vv.get(&o.origin).copied().unwrap_or(0) >= o.seq));
            !all_have
        });
        before - g.objs.len()
    }

    pub fn tombstone_count(&self) -> usize {
        self.inner.lock().objs.values().filter(|o| o.val.is_none()).count()
    }

    pub fn save(&self) {
        let snap = {
            let g = self.inner.lock();
            Snapshot {
                node: g.node.clone(),
                seq: g.seq,
                last_wall: g.last_wall,
                last_ctr: g.last_ctr,
                objs: g.objs.values().filter(|o| o.origin != "seed").cloned().collect(),
                vv: g.vv.clone(),
            }
        };
        let tmp = self.path.with_extension("tmp");
        if let Ok(data) = serde_json::to_vec(&snap) {
            if std::fs::write(&tmp, data).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
        self.save_side_files();
    }

    pub fn save_side_files(&self) {
        let dirty = std::mem::replace(&mut *self.history_dirty.lock(), false);
        if !dirty {
            return;
        }
        let write = |name: &str, data: Vec<u8>| {
            let p = self.path.with_file_name(name);
            let tmp = p.with_extension("tmp");
            if std::fs::write(&tmp, data).is_ok() {
                let _ = std::fs::rename(&tmp, &p);
            }
        };
        if let Ok(d) = serde_json::to_vec(&*self.history.lock()) {
            write("history.json", d);
        }
        if let Ok(d) = serde_json::to_vec(&*self.conflicts.lock()) {
            write("conflicts.json", d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn store(node: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("atom-test-{}-{}", node, crate::state::random_hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        Store::open(dir.join("config.json"), node).unwrap()
    }

    #[test]
    fn noop_write_is_ignored() {
        let s = store("a");
        s.put("rewrites", "1", json!({"domain": "x"}));
        let v = s.vv();
        s.put("rewrites", "1", json!({"domain": "x"}));
        assert_eq!(s.vv(), v);
        assert_eq!(s.history(10, "", "").len(), 1);
    }

    #[test]
    fn sequential_edits_are_not_conflicts() {
        let (a, b) = (store("a"), store("b"));
        a.put("rewrites", "1", json!({"domain": "x", "answer": "1.1.1.1"}));
        b.apply_remote(a.pull(&b.vv()));
        b.put("rewrites", "1", json!({"domain": "x", "answer": "2.2.2.2"}));
        a.apply_remote(b.pull(&a.vv()));
        assert!(a.conflicts().is_empty());
        assert_eq!(a.get("rewrites", "1").unwrap()["answer"], "2.2.2.2");
    }

    #[test]
    fn concurrent_edits_are_reported() {
        let (a, b) = (store("a"), store("b"));
        a.put("rewrites", "1", json!({"domain": "x", "answer": "1.1.1.1"}));
        b.apply_remote(a.pull(&b.vv()));
        a.put("rewrites", "1", json!({"domain": "x", "answer": "3.3.3.3"}));
        b.put("rewrites", "1", json!({"domain": "x", "answer": "4.4.4.4"}));
        a.apply_remote(b.pull(&a.vv()));
        b.apply_remote(a.pull(&b.vv()));
        assert_eq!(a.get("rewrites", "1"), b.get("rewrites", "1"));
        // Le nœud qui reçoit la version concurrente la signale ; l'autre garde sa valeur gagnante.
        assert_eq!(a.conflicts().len() + b.conflicts().len(), 1);
    }

    #[test]
    fn tombstones_wait_for_peers() {
        let (a, b) = (store("a"), store("b"));
        a.put("zones", "z", json!({"name": "z.lan"}));
        a.delete("zones", "z");
        assert_eq!(a.compact(0, &["b".to_string()]), 0);
        b.apply_remote(a.pull(&b.vv()));
        a.note_peer_vv("b", b.vv());
        assert_eq!(a.compact(0, &["b".to_string()]), 1);
    }

    #[test]
    fn restore_replaces_state() {
        let s = store("a");
        s.put("zones", "1", json!({"name": "a.lan"}));
        let snap = s.export();
        s.put("zones", "2", json!({"name": "b.lan"}));
        s.put("zones", "1", json!({"name": "changed.lan"}));
        let (put, del) = s.restore(&snap, true, "test");
        assert_eq!((put, del), (1, 1));
        assert_eq!(s.get("zones", "1").unwrap()["name"], "a.lan");
        assert!(s.get("zones", "2").is_none());
    }
}
