//! Clients DNS vers les serveurs amont : UDP/TCP, DNS-over-TLS, DNS-over-HTTPS.
//! Suivi de l'état de chaque upstream et transmission selon la priorité.

use crate::dnswire;
use crate::store::now_ms;
use anyhow::{anyhow, bail, Result};
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Clone, Debug)]
pub enum Proto {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Tls { host: String, port: u16, bootstrap: Option<IpAddr> },
    Https { url: String, host: String, port: u16, bootstrap: Option<IpAddr> },
}

pub struct Upstream {
    pub id: String,
    pub name: String,
    pub address: String,
    pub order: f64,
    pub domains: Vec<String>,
    pub proto: Proto,
    https: Option<reqwest::Client>,
}

#[derive(Clone, Serialize, Default, Debug)]
pub struct Health {
    pub up: Option<bool>,
    pub latency_ms: Option<u64>,
    pub last_check: u64,
    pub last_error: Option<String>,
    pub ok_count: u64,
    pub fail_count: u64,
}

pub type HealthMap = Arc<Mutex<HashMap<String, Health>>>;

pub fn parse_address(addr: &str, bootstrap: &str) -> Result<Proto> {
    let addr = addr.trim();
    let bootstrap = bootstrap.trim();
    let boot: Option<IpAddr> = if bootstrap.is_empty() {
        None
    } else {
        Some(bootstrap.parse().map_err(|_| anyhow!("adresse de bootstrap invalide"))?)
    };
    fn host_port(s: &str, default: u16) -> Result<(String, u16)> {
        if let Some(rest) = s.strip_prefix('[') {
            let (h, tail) = rest.split_once(']').ok_or_else(|| anyhow!("adresse IPv6 invalide"))?;
            let port = match tail.strip_prefix(':') {
                Some(p) => p.parse()?,
                None => default,
            };
            return Ok((h.to_string(), port));
        }
        if s.parse::<std::net::Ipv6Addr>().is_ok() {
            return Ok((s.to_string(), default));
        }
        match s.rsplit_once(':') {
            Some((h, p)) => Ok((h.to_string(), p.parse().map_err(|_| anyhow!("port invalide"))?)),
            None => Ok((s.to_string(), default)),
        }
    }
    if let Some(rest) = addr.strip_prefix("https://") {
        let (hostport, _) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = host_port(hostport, 443)?;
        let url = if rest.contains('/') { addr.to_string() } else { format!("{addr}/dns-query") };
        let b = boot.or_else(|| host.parse().ok());
        return Ok(Proto::Https { url, host, port, bootstrap: b });
    }
    if let Some(rest) = addr.strip_prefix("tls://") {
        let (host, port) = host_port(rest, 853)?;
        let b = boot.or_else(|| host.parse().ok());
        return Ok(Proto::Tls { host, port, bootstrap: b });
    }
    let (tcp, rest) = if let Some(r) = addr.strip_prefix("tcp://") {
        (true, r)
    } else if let Some(r) = addr.strip_prefix("udp://") {
        (false, r)
    } else {
        (false, addr)
    };
    let (host, port) = host_port(rest, 53)?;
    let ip: IpAddr = host.parse().map_err(|_| anyhow!("une adresse IP est attendue pour un upstream UDP/TCP"))?;
    let sa = SocketAddr::new(ip, port);
    Ok(if tcp { Proto::Tcp(sa) } else { Proto::Udp(sa) })
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions TLS")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

fn rand_u16() -> u16 {
    let mut b = [0u8; 2];
    let _ = getrandom::fill(&mut b);
    u16::from_be_bytes(b)
}

impl Upstream {
    pub fn new(id: &str, name: &str, address: &str, bootstrap: &str, order: f64, domains: Vec<String>) -> Result<Self> {
        let proto = parse_address(address, bootstrap)?;
        let https = if let Proto::Https { host, port, bootstrap, .. } = &proto {
            let mut b = reqwest::Client::builder().timeout(Duration::from_secs(10)).pool_idle_timeout(Duration::from_secs(60));
            if let Some(ip) = bootstrap {
                b = b.resolve(host, SocketAddr::new(*ip, *port));
            }
            Some(b.build()?)
        } else {
            None
        };
        Ok(Self { id: id.into(), name: name.into(), address: address.into(), order, domains, proto, https })
    }

    /// Envoie la requête et retourne la réponse brute (l'ID de la réponse est celui de `req`).
    pub async fn exchange(&self, req: &[u8], tmo: Duration) -> Result<Vec<u8>> {
        let mut q = req.to_vec();
        let wire_id = rand_u16();
        let orig = u16::from_be_bytes([req[0], req[1]]);
        dnswire::set_id(&mut q, wire_id);
        let fut = self.exchange_inner(&q, wire_id);
        let mut resp = tokio::time::timeout(tmo, fut).await.map_err(|_| anyhow!("délai dépassé"))??;
        dnswire::set_id(&mut resp, orig);
        Ok(resp)
    }

    async fn exchange_inner(&self, q: &[u8], id: u16) -> Result<Vec<u8>> {
        match &self.proto {
            Proto::Udp(sa) => {
                let bind = if sa.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                let sock = UdpSocket::bind(bind).await?;
                sock.connect(sa).await?;
                sock.send(q).await?;
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = sock.recv(&mut buf).await?;
                    if n >= 12 && u16::from_be_bytes([buf[0], buf[1]]) == id {
                        buf.truncate(n);
                        if dnswire::response_info(&buf).map_or(false, |i| i.truncated) {
                            return tcp_exchange(*sa, q, id).await;
                        }
                        return Ok(buf);
                    }
                }
            }
            Proto::Tcp(sa) => tcp_exchange(*sa, q, id).await,
            Proto::Tls { host, port, bootstrap } => {
                let sa = match bootstrap {
                    Some(ip) => SocketAddr::new(*ip, *port),
                    None => tokio::net::lookup_host((host.as_str(), *port))
                        .await?
                        .next()
                        .ok_or_else(|| anyhow!("résolution de {host} impossible"))?,
                };
                let tcp = TcpStream::connect(sa).await?;
                tcp.set_nodelay(true).ok();
                let name = rustls::pki_types::ServerName::try_from(host.clone())?;
                let conn = tokio_rustls::TlsConnector::from(tls_config());
                let mut tls = conn.connect(name, tcp).await?;
                framed(&mut tls, q, id).await
            }
            Proto::Https { url, .. } => {
                let c = self.https.as_ref().ok_or_else(|| anyhow!("client HTTPS absent"))?;
                let r = c
                    .post(url)
                    .header("content-type", "application/dns-message")
                    .header("accept", "application/dns-message")
                    .body(q.to_vec())
                    .send()
                    .await?;
                if !r.status().is_success() {
                    bail!("HTTP {}", r.status());
                }
                let b = r.bytes().await?.to_vec();
                if b.len() < 12 {
                    bail!("réponse trop courte");
                }
                Ok(b)
            }
        }
    }
}

async fn tcp_exchange(sa: SocketAddr, q: &[u8], id: u16) -> Result<Vec<u8>> {
    let mut s = TcpStream::connect(sa).await?;
    s.set_nodelay(true).ok();
    framed(&mut s, q, id).await
}

async fn framed<S: AsyncReadExt + AsyncWriteExt + Unpin>(s: &mut S, q: &[u8], id: u16) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(q.len() + 2);
    out.extend_from_slice(&(q.len() as u16).to_be_bytes());
    out.extend_from_slice(q);
    s.write_all(&out).await?;
    s.flush().await?;
    let mut lb = [0u8; 2];
    s.read_exact(&mut lb).await?;
    let len = u16::from_be_bytes(lb) as usize;
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    if buf.len() < 12 || u16::from_be_bytes([buf[0], buf[1]]) != id {
        bail!("réponse invalide");
    }
    Ok(buf)
}

pub fn record(health: &HealthMap, id: &str, r: &Result<u64, String>) {
    let mut g = health.lock();
    let h = g.entry(id.to_string()).or_default();
    h.last_check = now_ms();
    match r {
        Ok(ms) => {
            h.up = Some(true);
            h.latency_ms = Some(*ms);
            h.last_error = None;
            h.ok_count += 1;
        }
        Err(e) => {
            h.up = Some(false);
            h.last_error = Some(e.clone());
            h.fail_count += 1;
        }
    }
}

/// Sonde un upstream avec une vraie requête. Retourne la latence en ms.
pub async fn probe(u: &Upstream, health: &HealthMap) -> Result<u64, String> {
    let name = u.domains.first().cloned().unwrap_or_else(|| "cloudflare.com".into());
    let q = dnswire::build_query(rand_u16(), &name, dnswire::T_A);
    let t = Instant::now();
    let r = match u.exchange(&q, Duration::from_secs(4)).await {
        Ok(resp) => match dnswire::response_info(&resp) {
            Some(i) if i.rcode != dnswire::RC_SERVFAIL && i.rcode != dnswire::RC_REFUSED => Ok(t.elapsed().as_millis() as u64),
            Some(i) => Err(format!("code de réponse {}", i.rcode)),
            None => Err("réponse illisible".to_string()),
        },
        Err(e) => Err(e.to_string()),
    };
    record(health, &u.id, &r);
    r
}

fn is_down(health: &HealthMap, id: &str) -> bool {
    let g = health.lock();
    match g.get(id) {
        Some(h) => h.up == Some(false) && now_ms().saturating_sub(h.last_check) < 30_000,
        None => false,
    }
}

/// Upstreams applicables à un nom, dans l'ordre de priorité.
pub fn candidates(all: &[Arc<Upstream>], name: &str) -> Vec<Arc<Upstream>> {
    let mut best_len = 0usize;
    let mut specific: Vec<Arc<Upstream>> = Vec::new();
    for u in all {
        for d in &u.domains {
            if name == d || name.ends_with(&format!(".{d}")) {
                if d.len() > best_len {
                    best_len = d.len();
                    specific.clear();
                }
                if d.len() == best_len {
                    specific.push(u.clone());
                }
            }
        }
    }
    if !specific.is_empty() {
        return specific;
    }
    all.iter().filter(|u| u.domains.is_empty()).cloned().collect()
}

/// Transmet la requête. Retourne la réponse et le nom de l'upstream qui a répondu.
pub async fn forward(
    all: &[Arc<Upstream>],
    health: &HealthMap,
    parallel: bool,
    name: &str,
    req: &[u8],
    tmo: Duration,
) -> Result<(Vec<u8>, String)> {
    let cands = candidates(all, name);
    if cands.is_empty() {
        bail!("aucun upstream actif");
    }
    let (mut up, down): (Vec<_>, Vec<_>) = cands.into_iter().partition(|u| !is_down(health, &u.id));
    up.extend(down);
    let ok_resp = |resp: &[u8]| dnswire::response_info(resp).map_or(false, |i| i.rcode != dnswire::RC_SERVFAIL);
    let mut last_err = anyhow!("aucune réponse");
    if parallel {
        let mut set = tokio::task::JoinSet::new();
        for u in up {
            let req = req.to_vec();
            let health = health.clone();
            set.spawn(async move {
                let t = Instant::now();
                let r = u.exchange(&req, tmo).await;
                let rec = match &r {
                    Ok(b) if dnswire::response_info(b).map_or(false, |i| i.rcode != dnswire::RC_SERVFAIL) => Ok(t.elapsed().as_millis() as u64),
                    Ok(_) => Err("SERVFAIL".to_string()),
                    Err(e) => Err(e.to_string()),
                };
                record(&health, &u.id, &rec);
                (r, u.name.clone(), rec.is_ok())
            });
        }
        while let Some(j) = set.join_next().await {
            if let Ok((r, name, good)) = j {
                match r {
                    Ok(b) if good => {
                        set.abort_all();
                        return Ok((b, name));
                    }
                    Ok(_) => last_err = anyhow!("SERVFAIL"),
                    Err(e) => last_err = e,
                }
            }
        }
        return Err(last_err);
    }
    for u in up {
        let t = Instant::now();
        match u.exchange(req, tmo).await {
            Ok(b) if ok_resp(&b) => {
                record(health, &u.id, &Ok(t.elapsed().as_millis() as u64));
                return Ok((b, u.name.clone()));
            }
            Ok(_) => {
                record(health, &u.id, &Err("SERVFAIL".into()));
                last_err = anyhow!("SERVFAIL de {}", u.name);
            }
            Err(e) => {
                record(health, &u.id, &Err(e.to_string()));
                last_err = e;
            }
        }
    }
    Err(last_err)
}
