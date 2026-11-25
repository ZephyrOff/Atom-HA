//! Magasin d'objets répliqué.
//!
//! Chaque objet (collection + id) porte une horloge logique hybride (HLC).
//! En cas de conflit, la valeur avec la plus grande HLC gagne, objet par objet.
//! Un vecteur de versions (origine -> dernier numéro de séquence) permet à un pair
//! de ne demander que ce qui lui manque.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::watch;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

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

pub struct Store {
    inner: Mutex<Inner>,
    path: PathBuf,
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
        Ok(Self {
            inner: Mutex::new(inner),
            path,
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
        });
    }

    pub fn put(&self, col: &str, id: &str, val: Value) {
        self.write(col, id, Some(val));
    }

    pub fn delete(&self, col: &str, id: &str) {
        self.write(col, id, None);
    }

    fn write(&self, col: &str, id: &str, val: Option<Value>) {
        {
            let mut g = self.inner.lock();
            let hlc = g.tick();
            g.seq += 1;
            let seq = g.seq;
            let node = g.node.clone();
            g.vv.insert(node.clone(), seq);
            g.objs.insert(
                key(col, id),
                Obj { col: col.into(), id: id.into(), val, hlc, origin: node, seq },
            );
        }
        self.bump(true);
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

    /// Applique des objets reçus d'un pair. Retourne vrai si l'état a changé.
    pub fn apply_remote(&self, objs: Vec<Obj>) -> bool {
        let mut changed = false;
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
                let newer = match g.objs.get(&k) {
                    Some(cur) => o.hlc > cur.hlc,
                    None => true,
                };
                if newer {
                    g.objs.insert(k, o);
                    changed = true;
                }
            }
        }
        if changed {
            self.bump(false);
        }
        changed
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
    }
}
