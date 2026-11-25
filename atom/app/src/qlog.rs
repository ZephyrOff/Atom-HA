//! Journal des requêtes, répliqué entre les nœuds.
//! Chaque entrée appartient à un nœud d'origine et porte un numéro de séquence croissant.

use crate::clients::ClientSet;
use crate::store::now_ms;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct LogEntry {
    pub node: String,
    pub seq: u64,
    pub ts: u64,
    pub client: String,
    pub name: String,
    pub qtype: String,
    /// allowed | blocked | rewritten | zone | error
    pub result: String,
    pub reason: String,
    pub list: String,
    pub upstream: String,
    pub cached: bool,
    pub ms: u32,
    pub rcode: u8,
}

#[derive(Default)]
struct Inner {
    per: HashMap<String, BTreeMap<u64, LogEntry>>,
    seq: u64,
    dirty: bool,
}

pub struct QLog {
    node: String,
    cap: usize,
    path: PathBuf,
    inner: Mutex<Inner>,
}

#[derive(Default, Debug)]
pub struct LogFilter {
    pub search: String,
    pub status: String,
    pub node: String,
    pub client: String,
    pub qtype: String,
    pub limit: usize,
    pub before: Option<u64>,
    pub from: Option<u64>,
    pub to: Option<u64>,
    /// Restreint aux clients (adresses ou plages) d'un client ou d'un groupe.
    pub ids: Option<ClientSet>,
}

#[derive(Serialize, Default)]
pub struct Facets {
    pub clients: Vec<String>,
    pub qtypes: Vec<String>,
}

#[derive(Serialize, Default)]
pub struct Stats {
    pub total: u64,
    pub blocked: u64,
    pub rewritten: u64,
    pub cached: u64,
    pub avg_ms: f64,
    pub hours: Vec<[u64; 2]>,
    pub top_domains: Vec<(String, u64)>,
    pub top_blocked: Vec<(String, u64)>,
    pub top_clients: Vec<(String, u64)>,
    pub per_node: HashMap<String, u64>,
}

impl QLog {
    pub fn open(path: PathBuf, node: &str, cap: usize) -> Self {
        let mut inner = Inner::default();
        if let Ok(data) = std::fs::read(&path) {
            if let Ok(list) = serde_json::from_slice::<Vec<LogEntry>>(&data) {
                for e in list {
                    if e.node == node && e.seq > inner.seq {
                        inner.seq = e.seq;
                    }
                    inner.per.entry(e.node.clone()).or_default().insert(e.seq, e);
                }
            }
        }
        Self { node: node.to_string(), cap, path, inner: Mutex::new(inner) }
    }

    pub fn append(&self, mut e: LogEntry) {
        let mut g = self.inner.lock();
        g.seq += 1;
        e.seq = g.seq;
        e.node = self.node.clone();
        e.ts = now_ms();
        let m = g.per.entry(self.node.clone()).or_default();
        m.insert(e.seq, e);
        while m.len() > self.cap {
            m.pop_first();
        }
        g.dirty = true;
    }

    pub fn apply_remote(&self, entries: Vec<LogEntry>) {
        let mut g = self.inner.lock();
        for e in entries {
            if e.node == self.node {
                continue;
            }
            let m = g.per.entry(e.node.clone()).or_default();
            m.insert(e.seq, e);
        }
        for m in g.per.values_mut() {
            while m.len() > self.cap {
                m.pop_first();
            }
        }
        g.dirty = true;
    }

    pub fn vv(&self) -> HashMap<String, u64> {
        let g = self.inner.lock();
        g.per
            .iter()
            .filter_map(|(k, m)| m.keys().next_back().map(|s| (k.clone(), *s)))
            .collect()
    }

    pub fn pull(&self, vv: &HashMap<String, u64>, limit: usize) -> Vec<LogEntry> {
        let g = self.inner.lock();
        let mut out = Vec::new();
        for (origin, m) in g.per.iter() {
            let from = vv.get(origin).copied().unwrap_or(0);
            out.extend(m.range(from + 1..).take(limit).map(|(_, e)| e.clone()));
        }
        out
    }

    pub fn query(&self, f: &LogFilter) -> Vec<LogEntry> {
        let g = self.inner.lock();
        let search = f.search.to_lowercase();
        let client = f.client.to_lowercase();
        let limit = f.limit.clamp(1, 1000);
        let mut all: Vec<LogEntry> = Vec::new();
        for (origin, m) in g.per.iter() {
            if !f.node.is_empty() && &f.node != origin {
                continue;
            }
            let mut n = 0;
            for e in m.values().rev() {
                if let Some(b) = f.before {
                    if e.ts >= b {
                        continue;
                    }
                }
                if let Some(t) = f.to {
                    if e.ts > t {
                        continue;
                    }
                }
                if let Some(fr) = f.from {
                    if e.ts < fr {
                        break;
                    }
                }
                if !f.status.is_empty() && f.status != "all" {
                    let ok = if f.status == "cached" { e.cached } else { e.result == f.status };
                    if !ok {
                        continue;
                    }
                }
                if let Some(m) = &f.ids {
                    if !m.contains_str(&e.client) {
                        continue;
                    }
                }
                if !client.is_empty() && !e.client.to_lowercase().contains(&client) {
                    continue;
                }
                if !f.qtype.is_empty() && !e.qtype.eq_ignore_ascii_case(&f.qtype) {
                    continue;
                }
                if !search.is_empty() {
                    let hay = format!("{} {} {} {} {}", e.name, e.client, e.reason, e.list, e.upstream).to_lowercase();
                    if !hay.contains(&search) {
                        continue;
                    }
                }
                all.push(e.clone());
                n += 1;
                if n >= limit {
                    break;
                }
            }
        }
        all.sort_by(|a, b| b.ts.cmp(&a.ts).then(b.seq.cmp(&a.seq)));
        all.truncate(limit);
        all
    }

    /// Activité par adresse sur les dernières 24 h : (adresse, requêtes, bloquées, dernière requête).
    pub fn clients_summary(&self) -> Vec<(String, u64, u64, u64)> {
        let g = self.inner.lock();
        let cutoff = now_ms().saturating_sub(24 * 3600 * 1000);
        let mut map: HashMap<String, (u64, u64, u64)> = HashMap::new();
        for m in g.per.values() {
            for e in m.values().rev() {
                if e.ts < cutoff {
                    break;
                }
                let r = map.entry(e.client.clone()).or_default();
                r.0 += 1;
                if e.result == "blocked" {
                    r.1 += 1;
                }
                r.2 = r.2.max(e.ts);
            }
        }
        map.into_iter().map(|(k, v)| (k, v.0, v.1, v.2)).collect()
    }

    pub fn facets(&self) -> Facets {
        let g = self.inner.lock();
        let mut clients: std::collections::BTreeSet<String> = Default::default();
        let mut qtypes: std::collections::BTreeSet<String> = Default::default();
        for m in g.per.values() {
            for e in m.values() {
                if clients.len() < 500 {
                    clients.insert(e.client.clone());
                }
                qtypes.insert(e.qtype.clone());
            }
        }
        Facets { clients: clients.into_iter().collect(), qtypes: qtypes.into_iter().collect() }
    }

    pub fn stats(&self, node_filter: &str, ids: Option<&ClientSet>) -> Stats {
        let g = self.inner.lock();
        let now = now_ms();
        let cutoff = now.saturating_sub(24 * 3600 * 1000);
        let mut s = Stats { hours: vec![[0, 0]; 24], ..Default::default() };
        let mut dom: HashMap<String, u64> = HashMap::new();
        let mut blk: HashMap<String, u64> = HashMap::new();
        let mut cli: HashMap<String, u64> = HashMap::new();
        let mut ms_sum = 0u64;
        let mut ms_n = 0u64;
        for (origin, m) in g.per.iter() {
            if !node_filter.is_empty() && node_filter != origin {
                continue;
            }
            for e in m.values().rev() {
                if e.ts < cutoff {
                    break;
                }
                if let Some(set) = ids {
                    if !set.contains_str(&e.client) {
                        continue;
                    }
                }
                s.total += 1;
                *s.per_node.entry(origin.clone()).or_default() += 1;
                let h = ((now - e.ts) / 3_600_000).min(23) as usize;
                let idx = 23 - h;
                s.hours[idx][0] += 1;
                *dom.entry(e.name.clone()).or_default() += 1;
                *cli.entry(e.client.clone()).or_default() += 1;
                match e.result.as_str() {
                    "blocked" => {
                        s.blocked += 1;
                        s.hours[idx][1] += 1;
                        *blk.entry(e.name.clone()).or_default() += 1;
                    }
                    "rewritten" => s.rewritten += 1,
                    _ => {}
                }
                if e.cached {
                    s.cached += 1;
                } else if e.result == "allowed" {
                    ms_sum += e.ms as u64;
                    ms_n += 1;
                }
            }
        }
        s.avg_ms = if ms_n > 0 { ms_sum as f64 / ms_n as f64 } else { 0.0 };
        s.top_domains = top(dom);
        s.top_blocked = top(blk);
        s.top_clients = top(cli);
        s
    }

    pub fn save_if_dirty(&self) {
        let list: Vec<LogEntry> = {
            let mut g = self.inner.lock();
            if !g.dirty {
                return;
            }
            g.dirty = false;
            g.per.values().flat_map(|m| m.values().cloned()).collect()
        };
        let tmp = self.path.with_extension("tmp");
        if let Ok(data) = serde_json::to_vec(&list) {
            if std::fs::write(&tmp, data).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }
}

fn top(m: HashMap<String, u64>) -> Vec<(String, u64)> {
    let mut v: Vec<_> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(10);
    v
}
