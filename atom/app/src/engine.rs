//! Moteur de résolution : instantané immuable de toute la configuration utile aux requêtes.

use crate::dnswire::{self, Query, Rr};
use crate::clients::{ClientSet, Identity};
use crate::filter::ParsedList;
use crate::model::{self, ClientCfg, GroupCfg, ListCfg, RecordCfg, RewriteCfg, Settings, TempAllow, UpstreamCfg, ZoneCfg};
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
    pub clients: Vec<String>,
    pub groups: Vec<String>,
}

impl RewriteEntry {
    pub fn global(ans: RwAns) -> Self {
        Self { ans, expires: None, clients: vec![], groups: vec![] }
    }
    fn scoped(&self) -> bool {
        !(self.clients.is_empty() && self.groups.is_empty())
    }
}

#[derive(Clone)]
struct ZRec {
    rr: Rr,
    target: Option<String>,
    clients: Vec<String>,
    groups: Vec<String>,
}

impl ZRec {
    fn scoped(&self) -> bool {
        !(self.clients.is_empty() && self.groups.is_empty())
    }
}

/// Garde les enregistrements qui concernent ce client ; un enregistrement ciblé remplace
/// ceux, généraux, du même type.
fn scope_filter(recs: Vec<ZRec>, id: &Identity) -> Vec<ZRec> {
    let ok: Vec<ZRec> = recs.into_iter().filter(|r| id.in_scope(&r.clients, &r.groups)).collect();
    let scoped_types: HashSet<u16> = ok.iter().filter(|r| r.scoped()).map(|r| r.rr.rtype).collect();
    ok.into_iter().filter(|r| r.scoped() || !scoped_types.contains(&r.rr.rtype)).collect()
}

/// État d'accès réseau d'un client ou d'un groupe.
#[derive(Clone, Debug, Default)]
pub struct AccessEntry {
    pub name: String,
    pub block_internet: bool,
    pub block_lan: bool,
    pub block_until: Option<u64>,
}

#[derive(Clone)]
pub struct ClientEntry {
    pub id: String,
    pub set: ClientSet,
    pub group: String,
    pub access: AccessEntry,
}

#[derive(Clone, Debug, Default)]
pub struct Access {
    pub internet: bool,
    pub lan: bool,
    pub who: String,
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
    /// Règles désactivées par `$badfilter`, toutes listes confondues.
    pub disabled: HashSet<String>,
    /// Signature de ce qui change le contenu du cache (upstreams, DNSSEC) : le cache n'est vidé que si elle change.
    pub cache_sig: String,
    rw_exact: HashMap<String, Vec<RewriteEntry>>,
    rw_wild: HashMap<String, Vec<RewriteEntry>>,
    zones: Vec<String>,
    zone_serial: HashMap<String, u32>,
    zrecs: HashMap<String, Vec<ZRec>>,
    zwild: HashMap<String, Vec<ZRec>>,
    znames: HashSet<String>,
    ptr: HashMap<String, Rr>,
    pub upstreams: Vec<Arc<Upstream>>,
    pub clients: Vec<ClientEntry>,
    pub groups: HashMap<String, AccessEntry>,
    /// Domaines autorisés temporairement : (domaine, fin en ms).
    pub temp_allow: Vec<(String, u64)>,
}

fn parents(name: &str) -> impl Iterator<Item = &str> {
    name.match_indices('.').map(move |(i, _)| &name[i + 1..])
}

impl Engine {
    pub fn empty() -> Self {
        Self {
            settings: Settings::default(),
            lists: vec![],
            disabled: HashSet::new(),
            cache_sig: String::new(),
            rw_exact: HashMap::new(),
            rw_wild: HashMap::new(),
            zones: vec![],
            zone_serial: HashMap::new(),
            zrecs: HashMap::new(),
            zwild: HashMap::new(),
            znames: HashSet::new(),
            ptr: HashMap::new(),
            upstreams: vec![],
            clients: vec![],
            groups: HashMap::new(),
            temp_allow: vec![],
        }
    }

    /// Domaine d'une autorisation temporaire encore valable pour ce nom (le domaine lui-même ou un parent).
    pub fn temp_allowed(&self, name: &str, now: u64) -> Option<&str> {
        self.temp_allow
            .iter()
            .find(|(d, until)| *until > now && (name == d || name.strip_suffix(d.as_str()).map_or(false, |p| p.ends_with('.'))))
            .map(|(d, _)| d.as_str())
    }

    /// Nom du client enregistré, pour les règles `$client='Nom'`.
    pub fn client_name(&self, id: &Identity) -> Option<&str> {
        let cid = id.client.as_ref()?;
        self.clients.iter().find(|c| &c.id == cid).map(|c| c.access.name.as_str())
    }

    /// Retrouve le client enregistré (le plus précis) et son groupe à partir de l'adresse.
    pub fn identify(&self, ip: IpAddr) -> Identity {
        let best = self
            .clients
            .iter()
            .filter_map(|c| c.set.specificity(ip).map(|s| (s, c)))
            .max_by_key(|(s, _)| *s)
            .map(|(_, c)| c);
        match best {
            Some(c) => Identity {
                client: Some(c.id.clone()),
                group: if !c.group.is_empty() && self.groups.contains_key(&c.group) { Some(c.group.clone()) } else { None },
            },
            None => Identity::default(),
        }
    }

    /// Accès réseau effectif : le blocage du client ou celui de son groupe.
    pub fn access(&self, id: &Identity, now: u64) -> Access {
        let mut a = Access::default();
        let mut apply = |e: &AccessEntry| {
            let live = e.block_until.map_or(true, |t| t > now);
            if live && (e.block_internet || e.block_lan) {
                a.internet |= e.block_internet;
                a.lan |= e.block_lan;
                if a.who.is_empty() {
                    a.who = e.name.clone();
                }
            }
        };
        if let Some(cid) = &id.client {
            if let Some(c) = self.clients.iter().find(|c| &c.id == cid) {
                apply(&c.access);
            }
        }
        if let Some(gid) = &id.group {
            if let Some(g) = self.groups.get(gid) {
                apply(g);
            }
        }
        a
    }

    pub fn rewrite_lookup(&self, name: &str, now: u64, id: &Identity) -> Option<Vec<RewriteEntry>> {
        let pick = |v: &Vec<RewriteEntry>| -> Vec<RewriteEntry> {
            let ok: Vec<RewriteEntry> = v
                .iter()
                .filter(|e| e.expires.map_or(true, |t| t > now) && id.in_scope(&e.clients, &e.groups))
                .cloned()
                .collect();
            // Une réécriture ciblée prime sur la réécriture générale.
            if ok.iter().any(|e| e.scoped()) {
                ok.into_iter().filter(|e| e.scoped()).collect()
            } else {
                ok
            }
        };
        if let Some(v) = self.rw_exact.get(name) {
            let l = pick(v);
            if !l.is_empty() {
                return Some(l);
            }
        }
        for p in parents(name) {
            if let Some(v) = self.rw_wild.get(p) {
                let l = pick(v);
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

    pub fn zone_answer(&self, q: &Query, ident: &Identity) -> Option<ZoneAnswer> {
        let name = q.name.as_str();
        if q.qtype == dnswire::T_PTR {
            if let Some(rr) = self.ptr.get(name) {
                return Some(ZoneAnswer { rcode: 0, answers: vec![rr.clone()], authority: vec![], cname_target: None });
            }
        }
        let zone = self.zone_for(name)?;
        let serial = self.zone_serial.get(zone).copied().unwrap_or(1);
        let soa = dnswire::rr_soa(zone, 60, serial);
        let mut recs: Vec<ZRec> = scope_filter(self.zrecs.get(name).cloned().unwrap_or_default(), ident);
        if recs.is_empty() {
            for p in parents(name) {
                if p.len() < zone.len() {
                    break;
                }
                if let Some(w) = self.zwild.get(p) {
                    let renamed: Vec<ZRec> = w
                        .iter()
                        .map(|z| {
                            let mut z = z.clone();
                            z.rr.name = name.to_string();
                            z
                        })
                        .collect();
                    recs = scope_filter(renamed, ident);
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
                    let p = Arc::new(ParsedList::parse("Règles personnalisées", &custom.text));
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
                    let p = Arc::new(ParsedList::parse(&cfg.name, &text));
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
                let e = RewriteEntry { ans, expires: r.expires_at, clients: r.clients.clone(), groups: r.groups.clone() };
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
            if r.ptr && r.clients.is_empty() && r.groups.is_empty() {
                if let Ok(ip) = r.value.trim().parse::<std::net::Ipv4Addr>() {
                    let rn = dnswire::reverse_name_v4(ip);
                    ptr.insert(rn.clone(), dnswire::rr_name(&rn, dnswire::T_PTR, r.ttl, &fq));
                }
            }
            match fq.strip_prefix("*.") {
                Some(base) => zwild.entry(base.to_string()).or_default().push(ZRec { rr, target, clients: r.clients.clone(), groups: r.groups.clone() }),
                None => {
                    for p in parents(&fq) {
                        if p.len() < r.zone.len() {
                            break;
                        }
                        znames.insert(p.to_string());
                    }
                    zrecs.entry(fq).or_default().push(ZRec { rr, target, clients: r.clients.clone(), groups: r.groups.clone() });
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
        let cache_sig = format!(
            "{}|{}",
            ups.iter().map(|(_, id, u)| format!("{id}:{}:{}:{}:{}", u.address, u.bootstrap, u.domains.join(","), u.backup)).collect::<Vec<_>>().join(";"),
            settings.dnssec
        );
        let upstreams = ups
            .into_iter()
            .filter_map(|(_, id, u)| {
                Upstream::new(&id, &u.name, &u.address, &u.bootstrap, u.domains.clone(), u.backup)
                    .map(Arc::new)
                    .map_err(|e| tracing::warn!("upstream {} ignoré : {e}", u.name))
                    .ok()
            })
            .collect();

        let mut groups: HashMap<String, AccessEntry> = HashMap::new();
        for (id, v, _) in store.list("groups") {
            if let Ok(g) = serde_json::from_value::<GroupCfg>(v) {
                groups.insert(
                    id,
                    AccessEntry { name: g.name, block_internet: g.block_internet, block_lan: g.block_lan, block_until: g.block_until },
                );
            }
        }
        let mut clients: Vec<ClientEntry> = Vec::new();
        for (id, v, _) in store.list("clients") {
            if let Ok(c) = serde_json::from_value::<ClientCfg>(v) {
                clients.push(ClientEntry {
                    id,
                    set: ClientSet::parse(&c.ids),
                    group: c.group,
                    access: AccessEntry { name: c.name, block_internet: c.block_internet, block_lan: c.block_lan, block_until: c.block_until },
                });
            }
        }

        let temp_allow: Vec<(String, u64)> = store
            .list("tempallow")
            .into_iter()
            .filter_map(|(_, v, _)| serde_json::from_value::<TempAllow>(v).ok())
            .map(|t| (t.domain, t.until))
            .collect();

        let disabled = crate::filter::disabled_rules(&lists);
        Engine { settings, lists, disabled, cache_sig, rw_exact, rw_wild, zones, zone_serial, zrecs, zwild, znames, ptr, upstreams, clients, groups, temp_allow }
    }
}

#[cfg(test)]
mod temp_tests {
    use super::*;

    #[test]
    fn temp_allow_matches_domain_and_subdomains_until_expiry() {
        let mut e = Engine::empty();
        e.temp_allow = vec![("exemple.com".into(), 2_000)];
        assert_eq!(e.temp_allowed("exemple.com", 1_000), Some("exemple.com"));
        assert_eq!(e.temp_allowed("cdn.exemple.com", 1_000), Some("exemple.com"));
        assert_eq!(e.temp_allowed("autreexemple.com", 1_000), None);
        assert_eq!(e.temp_allowed("exemple.com", 3_000), None);
    }
}
