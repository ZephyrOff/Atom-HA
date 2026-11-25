//! Traitement d'une requête DNS : réécritures, zones, accès réseau, filtrage, cache, upstreams.

use crate::clients::{is_private, Identity};
use crate::dnswire::{self, Query, Rr};
use crate::engine::{Engine, RewriteEntry, RwAns};
use crate::filter::{self, HitKind, Rw};
use crate::qlog::LogEntry;
use crate::state::{App, CacheEntry};
use crate::store::now_ms;
use crate::upstream;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Outcome {
    pub resp: Vec<u8>,
    pub result: &'static str,
    pub reason: String,
    pub list: String,
    pub upstream: String,
    pub cached: bool,
    pub ad: bool,
}

fn out(resp: Vec<u8>, result: &'static str) -> Outcome {
    Outcome { resp, result, reason: String::new(), list: String::new(), upstream: String::new(), cached: false, ad: false }
}

/// Refus lié au blocage d'accès réseau d'un client.
fn deny(q: &Query, what: &str, who: &str) -> Outcome {
    let mut o = out(dnswire::build_response(q, dnswire::RC_NXDOMAIN, false, &[], &[]), "blocked");
    o.reason = format!("Accès {what} bloqué ({who})");
    o.list = "Accès réseau".into();
    o
}

/// Réponse pour une réécriture ou un blocage par adresse.
async fn answer_rewrite(app: &Arc<App>, eng: &Engine, q: &Query, rw: &[RewriteEntry], ttl: u32, ident: &Identity) -> Vec<u8> {
    let mut answers: Vec<Rr> = Vec::new();
    let mut cname: Option<String> = None;
    for e in rw {
        match &e.ans {
            RwAns::Ip(IpAddr::V4(ip)) if q.qtype == dnswire::T_A => answers.push(dnswire::rr_a(&q.name, ttl, *ip)),
            RwAns::Ip(IpAddr::V6(ip)) if q.qtype == dnswire::T_AAAA => answers.push(dnswire::rr_aaaa(&q.name, ttl, *ip)),
            RwAns::Cname(c) if q.qtype == dnswire::T_A || q.qtype == dnswire::T_AAAA => cname = Some(c.clone()),
            _ => {}
        }
    }
    if let Some(c) = cname {
        answers.push(dnswire::rr_name(&q.name, dnswire::T_CNAME, ttl, &c));
        answers.extend(resolve_addrs(app, eng, &c, q.qtype, 0, ident).await);
    }
    dnswire::build_response(q, 0, false, &answers, &[])
}

fn answer_block(eng: &Engine, q: &Query, rw: Option<&Rw>) -> Vec<u8> {
    match rw {
        Some(Rw::NxDomain) => return dnswire::build_response(q, dnswire::RC_NXDOMAIN, false, &[], &[]),
        Some(Rw::Refused) => return dnswire::build_response(q, dnswire::RC_REFUSED, false, &[], &[]),
        _ => {}
    }
    match eng.settings.block_mode.as_str() {
        "nxdomain" => dnswire::build_response(q, dnswire::RC_NXDOMAIN, false, &[], &[]),
        "refused" => dnswire::build_response(q, dnswire::RC_REFUSED, false, &[], &[]),
        _ => {
            let mut a = Vec::new();
            if q.qtype == dnswire::T_A {
                a.push(dnswire::rr_a(&q.name, 10, Ipv4Addr::UNSPECIFIED));
            } else if q.qtype == dnswire::T_AAAA {
                a.push(dnswire::rr_aaaa(&q.name, 10, Ipv6Addr::UNSPECIFIED));
            }
            dnswire::build_response(q, 0, false, &a, &[])
        }
    }
}

/// Retourne les adresses (A ou AAAA) d'un nom en consultant d'abord le local, puis les upstreams.
pub fn resolve_addrs<'a>(
    app: &'a Arc<App>,
    eng: &'a Engine,
    name: &'a str,
    qtype: u16,
    depth: u8,
    ident: &'a Identity,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<Rr>> + Send + 'a>> {
    Box::pin(async move {
        if depth > 5 {
            return vec![];
        }
        let q = Query { id: 0, rd: true, name: name.to_string(), qtype, qclass: 1, qend: 0, edns_size: None };
        if let Some(rw) = eng.rewrite_lookup(name, now_ms(), ident) {
            let mut v = Vec::new();
            for e in rw {
                match e.ans {
                    RwAns::Ip(IpAddr::V4(ip)) if qtype == dnswire::T_A => v.push(dnswire::rr_a(name, 60, ip)),
                    RwAns::Ip(IpAddr::V6(ip)) if qtype == dnswire::T_AAAA => v.push(dnswire::rr_aaaa(name, 60, ip)),
                    RwAns::Cname(c) => {
                        v.push(dnswire::rr_name(name, dnswire::T_CNAME, 60, &c));
                        v.extend(resolve_addrs(app, eng, &c, qtype, depth + 1, ident).await);
                    }
                    _ => {}
                }
            }
            return v;
        }
        if let Some(z) = eng.zone_answer(&q, ident) {
            let mut v = z.answers;
            if let Some(t) = z.cname_target {
                v.extend(resolve_addrs(app, eng, &t, qtype, depth + 1, ident).await);
            }
            return v;
        }
        let req = dnswire::build_query(1, name, qtype);
        let tmo = Duration::from_millis(eng.settings.timeout_ms);
        let parallel = eng.settings.upstream_mode == "parallel";
        match upstream::forward(&eng.upstreams, &app.health, parallel, name, &req, tmo).await {
            Ok((resp, _)) => {
                let info = dnswire::response_info(&resp).unwrap_or_default();
                info.addrs
                    .into_iter()
                    .filter(|(t, _, _)| *t == qtype)
                    .map(|(t, rd, ttl)| Rr { name: name.to_string(), rtype: t, ttl, rdata: rd })
                    .collect()
            }
            Err(_) => vec![],
        }
    })
}

async fn forward_cached(app: &Arc<App>, eng: &Engine, q: &Query, req: &[u8]) -> Result<(Vec<u8>, String, bool), String> {
    let key = (q.name.clone(), q.qtype, q.qclass);
    let use_cache = eng.settings.cache_enabled && q.qtype != 255;
    if use_cache {
        let mut c = app.cache.lock();
        if let Some(e) = c.get(&key) {
            if e.expires > Instant::now() {
                let mut d = e.data.clone();
                dnswire::set_id(&mut d, q.id);
                app.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok((d, "cache".into(), true));
            }
            c.remove(&key);
        }
        app.cache_misses.fetch_add(1, Ordering::Relaxed);
    }
    let tmo = Duration::from_millis(eng.settings.timeout_ms);
    let parallel = eng.settings.upstream_mode == "parallel";
    let sent;
    let req = if eng.settings.dnssec {
        sent = dnswire::with_dnssec(req);
        &sent[..]
    } else {
        req
    };
    match upstream::forward(&eng.upstreams, &app.health, parallel, &q.name, req, tmo).await {
        Ok((mut resp, name)) => {
            dnswire::set_id(&mut resp, q.id);
            if use_cache {
                if let Some(info) = dnswire::response_info(&resp) {
                    if (info.rcode == 0 || info.rcode == dnswire::RC_NXDOMAIN) && !info.truncated {
                        let ttl = info.ttl.unwrap_or(30).clamp(5, 3600);
                        let mut c = app.cache.lock();
                        if c.len() >= eng.settings.cache_size {
                            let now = Instant::now();
                            c.retain(|_, e| e.expires > now);
                            if c.len() >= eng.settings.cache_size {
                                c.clear();
                            }
                        }
                        c.insert(key, CacheEntry { data: resp.clone(), expires: Instant::now() + Duration::from_secs(ttl as u64) });
                    }
                }
            }
            Ok((resp, name, false))
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Évalue une requête sans l'enregistrer dans le journal.
pub async fn resolve(app: &Arc<App>, req: &[u8], q: &Query, client: IpAddr) -> Outcome {
    let eng = app.engine.load_full();
    let now = now_ms();
    let ident = eng.identify(client);
    let acc = eng.access(&ident, now);

    // 1. réécritures
    if eng.settings.rewrites_enabled {
        if let Some(rw) = eng.rewrite_lookup(&q.name, now, &ident) {
            let lan = rw.iter().all(|e| matches!(&e.ans, RwAns::Ip(ip) if is_private(ip)));
            if lan && acc.lan {
                return deny(q, "LAN", &acc.who);
            }
            if !lan && acc.internet {
                return deny(q, "Internet", &acc.who);
            }
            let resp = answer_rewrite(app, &eng, q, &rw, 60, &ident).await;
            let mut o = out(resp, "rewritten");
            o.reason = "réécriture DNS".into();
            return o;
        }
    }

    // 2. zones locales
    if let Some(z) = eng.zone_answer(q, &ident) {
        if acc.lan {
            return deny(q, "LAN", &acc.who);
        }
        let mut answers = z.answers;
        if let Some(t) = &z.cname_target {
            if q.qtype == dnswire::T_A || q.qtype == dnswire::T_AAAA {
                answers.extend(resolve_addrs(app, &eng, t, q.qtype, 0, &ident).await);
            }
        }
        let resp = dnswire::build_response(q, z.rcode, true, &answers, &z.authority);
        return out(resp, "zone");
    }

    // 3. filtrage
    let paused = eng.settings.pause_until.map_or(false, |t| t > now);
    let mut reason = String::new();
    let mut list = String::new();
    if let Some(d) = eng.temp_allowed(&q.name, now).filter(|_| eng.settings.filtering_enabled && !paused) {
        reason = format!("autorisation temporaire ({d})");
        list = "Autorisation temporaire".into();
    } else if eng.settings.filtering_enabled && !paused {
        let fctx = filter::Ctx { ip: client, client_name: eng.client_name(&ident), qtype: q.qtype };
        if let Some(hit) = filter::check(&eng.lists, &q.name, &fctx, &eng.disabled) {
            match hit.kind {
                HitKind::Block => {
                    let mut o = out(answer_block(&eng, q, None), "blocked");
                    o.reason = hit.rule;
                    o.list = hit.list;
                    return o;
                }
                HitKind::Rewrite(rw) => {
                    let mut o = match &rw {
                        Rw::Ip(ip) => {
                            let e = [RewriteEntry::global(RwAns::Ip(*ip))];
                            out(answer_rewrite(app, &eng, q, &e, 60, &ident).await, "rewritten")
                        }
                        Rw::Cname(c) => {
                            let e = [RewriteEntry::global(RwAns::Cname(c.clone()))];
                            out(answer_rewrite(app, &eng, q, &e, 60, &ident).await, "rewritten")
                        }
                        other => out(answer_block(&eng, q, Some(other)), "blocked"),
                    };
                    o.reason = hit.rule;
                    o.list = hit.list;
                    return o;
                }
                HitKind::Allow => {
                    reason = hit.rule;
                    list = hit.list;
                }
            }
        }
    }

    // 4. accès Internet bloqué pour ce client
    if acc.internet {
        return deny(q, "Internet", &acc.who);
    }

    // 5. cache et upstreams
    match forward_cached(app, &eng, q, req).await {
        Ok((resp, up, cached)) => {
            if acc.lan {
                // Une réponse qui pointe vers le réseau local est refusée (comme une protection anti-rebinding).
                let private = dnswire::response_info(&resp)
                    .map(|i| {
                        i.addrs.iter().any(|(t, rd, _)| {
                            let ip = if *t == dnswire::T_A && rd.len() == 4 {
                                Some(IpAddr::from([rd[0], rd[1], rd[2], rd[3]]))
                            } else if *t == dnswire::T_AAAA && rd.len() == 16 {
                                let mut b = [0u8; 16];
                                b.copy_from_slice(rd);
                                Some(IpAddr::from(b))
                            } else {
                                None
                            };
                            ip.map_or(false, |ip| is_private(&ip))
                        })
                    })
                    .unwrap_or(false);
                if private {
                    return deny(q, "LAN", &acc.who);
                }
            }
            let ad = eng.settings.dnssec && dnswire::is_authenticated(&resp);
            Outcome { resp, result: "allowed", reason, list, upstream: up, cached, ad }
        }
        Err(e) => {
            let resp = dnswire::build_response(q, dnswire::RC_SERVFAIL, false, &[], &[]);
            Outcome { resp, result: "error", reason: e, list, upstream: String::new(), cached: false, ad: false }
        }
    }
}

/// Point d'entrée du serveur : traite, journalise, retourne la réponse.
pub async fn handle(app: &Arc<App>, req: &[u8], client: IpAddr) -> Option<Vec<u8>> {
    let q = dnswire::parse_query(req)?;
    let start = Instant::now();
    let o = resolve(app, req, &q, client).await;
    if app.engine.load().settings.log_enabled {
        let rcode = o.resp.get(3).map(|b| b & 0x0F).unwrap_or(0);
        app.qlog.append(LogEntry {
            client: client.to_string(),
            name: q.name.clone(),
            qtype: dnswire::type_name(q.qtype),
            result: o.result.into(),
            reason: o.reason,
            list: o.list,
            upstream: o.upstream,
            cached: o.cached,
            ad: o.ad,
            ms: start.elapsed().as_millis() as u32,
            rcode,
            ..Default::default()
        });
    }
    Some(o.resp)
}
