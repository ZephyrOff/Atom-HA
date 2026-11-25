//! Moteur de résolution : instantané immuable de toute la configuration utile aux requêtes.

use crate::dnswire::{self, Query, Rr};
use crate::filter::ParsedList;
use crate::model::{self, ListCfg, RecordCfg, RewriteCfg, Settings, UpstreamCfg, ZoneCfg};
use crate::state::App;
use crate::upstream::Upstream;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub enum RwAns {
    Ip(IpAddr),
    Cname(String),
}

#[derive(Clone, Debug)]
pub struct RewriteEntry {
    pub ans: RwAns,
    pub expires: Option<u64>,
}

#[derive(Clone)]
struct ZRec {
    rr: Rr,
    target: Option<String>,
}

pub struct ZoneAnswer {
    pub rcode: u8,
    pub answers: Vec<Rr>,
    pub authority: Vec<Rr>,
    pub cname_target: Option<String>,
}

pub struct Engine {
    pub settings: Settings,
    pub lists: Vec<Arc<ParsedList>>,
    rw_exact: HashMap<String, Vec<RewriteEntry>>,
    rw_wild: HashMap<String, Vec<RewriteEntry>>,
    zones: Vec<String>,
    zone_serial: HashMap<String, u32>,
    zrecs: HashMap<String, Vec<ZRec>>,
    zwild: HashMap<String, Vec<ZRec>>,
    znames: HashSet<String>,
    ptr: HashMap<String, Rr>,
    pub upstreams: Vec<Arc<Upstream>>,
}

fn parents(name: &str) -> impl Iterator<Item = &str> {
    name.match_indices('.').map(move |(i, _)| &name[i + 1..])
}

impl Engine {
    pub fn empty() -> Self {
        Self {
            settings: Settings::default(),
            lists: vec![],
            rw_exact: HashMap::new(),
            rw_wild: HashMap::new(),
            zones: vec![],
            zone_serial: HashMap::new(),
            zrecs: HashMap::new(),
            zwild: HashMap::new(),
            znames: HashSet::new(),
            ptr: HashMap::new(),
            upstreams: vec![],
        }
    }

    pub fn rewrite_lookup(&self, name: &str, now: u64) -> Option<Vec<RewriteEntry>> {
        let live = |v: &Vec<RewriteEntry>| -> Vec<RewriteEntry> {
            v.iter().filter(|e| e.expires.map_or(true, |t| t > now)).cloned().collect()
        };
        if let Some(v) = self.rw_exact.get(name) {
            let l = live(v);
            if !l.is_empty() {
                return Some(l);
            }
        }
        for p in parents(name) {
            if let Some(v) = self.rw_wild.get(p) {
                let l = live(v);
                if !l.is_empty() {
                    return Some(l);
                }
            }
        }
        None
    }

    fn zone_for(&self, name: &str) -> Option<&String> {
        self.zones.iter().find(|z| name == z.as_str() || name.ends_with(&format!(".{z}")))
    }

    pub fn zone_answer(&self, q: &Query) -> Option<ZoneAnswer> {
        let name = q.name.as_str();
        if q.qtype == dnswire::T_PTR {
            if let Some(rr) = self.ptr.get(name) {
                return Some(ZoneAnswer { rcode: 0, answers: vec![rr.clone()], authority: vec![], cname_target: None });
            }
        }
        let zone = self.zone_for(name)?;
        let serial = self.zone_serial.get(zone).copied().unwrap_or(1);
        let soa = dnswire::rr_soa(zone, 60, serial);
        let mut recs: Vec<ZRec> = self.zrecs.get(name).cloned().unwrap_or_default();
        if recs.is_empty() {
            for p in parents(name) {
                if p.len() < zone.len() {
                    break;
                }
                if let Some(w) = self.zwild.get(p) {
                    recs = w
                        .iter()
                        .map(|z| {
                            let mut z = z.clone();
                            z.rr.name = name.to_string();
                            z
                        })
                        .collect();
                    break;
                }
            }
        }
        let want = |t: u16| q.qtype == 255 || q.qtype == t;
        let matching: Vec<Rr> = recs.iter().filter(|r| want(r.rr.rtype)).map(|r| r.rr.clone()).collect();
        if !matching.is_empty() {
            return Some(ZoneAnswer { rcode: 0, answers: matching, authority: vec![], cname_target: None });
        }
        if q.qtype != dnswire::T_CNAME {
            if let Some(c) = recs.iter().find(|r| r.rr.rtype == dnswire::T_CNAME) {
                return Some(ZoneAnswer {
                    rcode: 0,
                    answers: vec![c.rr.clone()],
                    authority: vec![],
                    cname_target: c.target.clone(),
                });
            }
        }
        if q.qtype == dnswire::T_SOA && name == zone {
            return Some(ZoneAnswer { rcode: 0, answers: vec![soa], authority: vec![], cname_target: None });
        }
        if !recs.is_empty() || self.znames.contains(name) || name == zone {
            return Some(ZoneAnswer { rcode: 0, answers: vec![], authority: vec![soa], cname_target: None });
        }
        Some(ZoneAnswer { rcode: dnswire::RC_NXDOMAIN, answers: vec![], authority: vec![soa], cname_target: None })
    }

    pub fn build(app: &Arc<App>) -> Engine {
        let store = &app.store;
        let settings: Settings = store
            .get("settings", "main")
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let now = crate::store::now_ms();

        // --- listes ---
        let mut lists: Vec<Arc<ParsedList>> = Vec::new();
        let mut keep: HashSet<String> = HashSet::new();
        let hash = |s: &str| {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            s.hash(&mut h);
            h.finish()
        };
        {
            let custom = store
                .get("rules", "main")
                .and_then(|v| serde_json::from_value::<model::CustomRules>(v).ok())
                .unwrap_or_default();
            let stamp = format!("c{}", hash(&custom.text));
            let mut pc = app.parse_cache.lock();
            let parsed = match pc.get("custom") {
                Some((s, p)) if *s == stamp => p.clone(),
                _ => {
                    let p = Arc::new(ParsedList::parse("custom", "Règles personnalisées", &custom.text));
                    pc.insert("custom".into(), (stamp, p.clone()));
                    p
                }
            };
            keep.insert("custom".into());
            lists.push(parsed);
        }
        for (id, v, _) in store.list("lists") {
            let Ok(cfg) = serde_json::from_value::<ListCfg>(v) else { continue };
            keep.insert(id.clone());
            if !cfg.enabled {
                continue;
            }
            let (stamp, loader): (String, Box<dyn Fn() -> Option<String>>) = if cfg.kind == "inline" {
                let c = cfg.content.clone();
                (format!("i{}", hash(&cfg.content)), Box::new(move || Some(c.clone())))
            } else {
                let meta = app.lists_meta.lock().get(&id).cloned();
                let Some(meta) = meta else { continue };
                if meta.updated_at == 0 {
                    continue;
                }
                let path = app.cfg.data_dir.join("lists").join(format!("{id}.txt"));
                (format!("u{}", meta.updated_at), Box::new(move || std::fs::read_to_string(&path).ok()))
            };
            let cached = {
                let pc = app.parse_cache.lock();
                pc.get(&id).filter(|(s, _)| *s == stamp).map(|(_, p)| p.clone())
            };
            let parsed = match cached {
                Some(p) => p,
                None => {
                    let Some(text) = loader() else { continue };
                    let p = Arc::new(ParsedList::parse(&id, &cfg.name, &text));
                    {
                        let mut m = app.lists_meta.lock();
                        if let Some(meta) = m.get_mut(&id) {
                            meta.rules = p.count;
                            meta.unsupported = p.unsupported;
                        }
                    }
                    app.parse_cache.lock().insert(id.clone(), (stamp, p.clone()));
                    p
                }
            };
            lists.push(parsed);
        }
        app.parse_cache.lock().retain(|k, _| keep.contains(k));

        // --- réécritures ---
        let mut rw_exact: HashMap<String, Vec<RewriteEntry>> = HashMap::new();
        let mut rw_wild: HashMap<String, Vec<RewriteEntry>> = HashMap::new();
        if settings.rewrites_enabled {
            for (_, v, _) in store.list("rewrites") {
                let Ok(r) = serde_json::from_value::<RewriteCfg>(v) else { continue };
                if !r.enabled {
                    continue;
                }
                let ans = match r.answer.parse::<IpAddr>() {
                    Ok(ip) => RwAns::Ip(ip),
                    Err(_) => RwAns::Cname(r.answer.clone()),
                };
                let e = RewriteEntry { ans, expires: r.expires_at };
                match r.domain.strip_prefix("*.") {
                    Some(base) => rw_wild.entry(base.to_string()).or_default().push(e),
                    None => rw_exact.entry(r.domain.clone()).or_default().push(e),
                }
            }
        }

        // --- zones ---
        let mut zones: Vec<String> = Vec::new();
        for (_, v, _) in store.list("zones") {
            if let Ok(z) = serde_json::from_value::<ZoneCfg>(v) {
                zones.push(z.name);
            }
        }
        zones.sort_by(|a, b| b.len().cmp(&a.len()));
        let mut zone_serial: HashMap<String, u32> = HashMap::new();
        let mut zrecs: HashMap<String, Vec<ZRec>> = HashMap::new();
        let mut zwild: HashMap<String, Vec<ZRec>> = HashMap::new();
        let mut znames: HashSet<String> = HashSet::new();
        let mut ptr: HashMap<String, Rr> = HashMap::new();
        for (_, v, hlc) in store.list("records") {
            let Ok(r) = serde_json::from_value::<RecordCfg>(v) else { continue };
            if !r.enabled {
                continue;
            }
            let fq = model::record_fqdn(&r.zone, &r.name);
            let Ok(rr) = dnswire::parse_record(&r.rtype, &fq, &r.value, r.ttl) else { continue };
            let target = if rr.rtype == dnswire::T_CNAME { Some(r.value.trim().trim_end_matches('.').to_ascii_lowercase()) } else { None };
            let serial = (hlc.wall / 1000) as u32;
            let s = zone_serial.entry(r.zone.clone()).or_insert(1);
            *s = (*s).max(serial);
            if r.ptr {
                if let Ok(ip) = r.value.trim().parse::<std::net::Ipv4Addr>() {
                    let rn = dnswire::reverse_name_v4(ip);
                    ptr.insert(rn.clone(), dnswire::rr_name(&rn, dnswire::T_PTR, r.ttl, &fq));
                }
            }
            match fq.strip_prefix("*.") {
                Some(base) => zwild.entry(base.to_string()).or_default().push(ZRec { rr, target }),
                None => {
                    for p in parents(&fq) {
                        if p.len() < r.zone.len() {
                            break;
                        }
                        znames.insert(p.to_string());
                    }
                    zrecs.entry(fq).or_default().push(ZRec { rr, target });
                }
            }
        }

        // --- upstreams ---
        let mut ups: Vec<(f64, String, UpstreamCfg)> = Vec::new();
        for (id, v, _) in store.list("upstreams") {
            if let Ok(u) = serde_json::from_value::<UpstreamCfg>(v) {
                if u.enabled {
                    ups.push((u.order, id, u));
                }
            }
        }
        ups.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.cmp(&b.1)));
        let upstreams = ups
            .into_iter()
            .filter_map(|(order, id, u)| {
                Upstream::new(&id, &u.name, &u.address, &u.bootstrap, order, u.domains.clone())
                    .map(Arc::new)
                    .map_err(|e| tracing::warn!("upstream {} ignoré : {e}", u.name))
                    .ok()
            })
            .collect();
        let _ = now;

        Engine { settings, lists, rw_exact, rw_wild, zones, zone_serial, zrecs, zwild, znames, ptr, upstreams }
    }
}
