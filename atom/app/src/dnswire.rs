//! Lecture et construction minimales de messages DNS (RFC 1035).

use std::net::{Ipv4Addr, Ipv6Addr};

pub const T_A: u16 = 1;
pub const T_NS: u16 = 2;
pub const T_CNAME: u16 = 5;
pub const T_SOA: u16 = 6;
pub const T_PTR: u16 = 12;
pub const T_MX: u16 = 15;
pub const T_TXT: u16 = 16;
pub const T_AAAA: u16 = 28;
pub const T_SRV: u16 = 33;
pub const T_OPT: u16 = 41;
pub const T_CAA: u16 = 257;

pub const RC_SERVFAIL: u8 = 2;
pub const RC_NXDOMAIN: u8 = 3;
pub const RC_REFUSED: u8 = 5;

pub fn type_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        257 => "CAA".into(),
        n => format!("TYPE{n}"),
    }
}

pub fn type_from_name(s: &str) -> Option<u16> {
    Some(match s.to_ascii_uppercase().as_str() {
        "A" => T_A,
        "NS" => T_NS,
        "CNAME" => T_CNAME,
        "SOA" => T_SOA,
        "PTR" => T_PTR,
        "MX" => T_MX,
        "TXT" => T_TXT,
        "AAAA" => T_AAAA,
        "SRV" => T_SRV,
        "CAA" => T_CAA,
        _ => return None,
    })
}

#[derive(Clone, Debug)]
pub struct Query {
    pub id: u16,
    pub rd: bool,
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Position juste après la section question.
    pub qend: usize,
    pub edns_size: Option<u16>,
}

impl Query {
    pub fn max_udp(&self) -> usize {
        match self.edns_size {
            Some(s) => (s as usize).clamp(512, 4096),
            None => 512,
        }
    }
}

/// Lit un nom (avec compression). Retourne le nom en minuscules sans point final,
/// et la position qui suit le nom dans le flux d'origine.
pub fn read_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut pos = start;
    let mut end = None;
    let mut out = String::new();
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            if end.is_none() {
                end = Some(pos + 1);
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            let b2 = *buf.get(pos + 1)? as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            pos = ((len & 0x3F) << 8) | b2;
            jumps += 1;
            if jumps > 20 {
                return None;
            }
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let label = buf.get(pos + 1..pos + 1 + len)?;
        if !out.is_empty() {
            out.push('.');
        }
        for &c in label {
            out.push((c as char).to_ascii_lowercase());
        }
        pos += 1 + len;
        if out.len() > 255 {
            return None;
        }
    }
    Some((out, end?))
}

pub fn parse_query(buf: &[u8]) -> Option<Query> {
    if buf.len() < 17 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 != 0 {
        return None; // c'est une réponse
    }
    if (flags >> 11) & 0xF != 0 {
        return None; // seulement QUERY
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    if qd != 1 {
        return None;
    }
    let (name, p) = read_name(buf, 12)?;
    let qtype = u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]);
    let qclass = u16::from_be_bytes([*buf.get(p + 2)?, *buf.get(p + 3)?]);
    let qend = p + 4;
    let mut edns_size = None;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let ns = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let ar = u16::from_be_bytes([buf[10], buf[11]]) as usize;
    let mut pos = qend;
    for i in 0..(an + ns + ar) {
        let Some((_, np)) = read_name(buf, pos) else { break };
        if np + 10 > buf.len() {
            break;
        }
        let t = u16::from_be_bytes([buf[np], buf[np + 1]]);
        let class = u16::from_be_bytes([buf[np + 2], buf[np + 3]]);
        let rdlen = u16::from_be_bytes([buf[np + 8], buf[np + 9]]) as usize;
        if t == T_OPT && i >= an + ns {
            edns_size = Some(class);
        }
        pos = np + 10 + rdlen;
    }
    Some(Query {
        id,
        rd: flags & 0x0100 != 0,
        name,
        qtype,
        qclass,
        qend,
        edns_size,
    })
}

#[derive(Clone, Debug)]
pub struct Rr {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

fn write_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let b = label.as_bytes();
        let n = b.len().min(63);
        out.push(n as u8);
        out.extend_from_slice(&b[..n]);
    }
    out.push(0);
}

pub fn build_response(q: &Query, rcode: u8, aa: bool, answers: &[Rr], authority: &[Rr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&q.id.to_be_bytes());
    let mut flags: u16 = 0x8000 | 0x0080 | rcode as u16;
    if q.rd {
        flags |= 0x0100;
    }
    if aa {
        flags |= 0x0400;
    }
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&(authority.len() as u16).to_be_bytes());
    let ar: u16 = if q.edns_size.is_some() { 1 } else { 0 };
    out.extend_from_slice(&ar.to_be_bytes());
    write_name(&mut out, &q.name);
    out.extend_from_slice(&q.qtype.to_be_bytes());
    out.extend_from_slice(&q.qclass.to_be_bytes());
    for r in answers.iter().chain(authority.iter()) {
        write_name(&mut out, &r.name);
        out.extend_from_slice(&r.rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&r.ttl.to_be_bytes());
        out.extend_from_slice(&(r.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&r.rdata);
    }
    if ar == 1 {
        out.push(0);
        out.extend_from_slice(&T_OPT.to_be_bytes());
        out.extend_from_slice(&1232u16.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    }
    out
}

/// Réduit une réponse trop grosse pour l'UDP : question seule avec le bit TC.
pub fn truncate_for_udp(resp: &[u8], q: &Query) -> Vec<u8> {
    if resp.len() <= q.max_udp() || resp.len() < q.qend {
        return resp.to_vec();
    }
    let mut out = resp[..q.qend].to_vec();
    out[2] |= 0x02; // TC
    for i in 6..12 {
        out[i] = 0;
    }
    out
}

pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    write_name(&mut out, name);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

pub fn set_id(buf: &mut [u8], id: u16) {
    if buf.len() >= 2 {
        buf[0..2].copy_from_slice(&id.to_be_bytes());
    }
}

#[derive(Debug, Default)]
pub struct RespInfo {
    pub rcode: u8,
    /// TTL minimal pour la mise en cache.
    pub ttl: Option<u32>,
    /// Adresses A / AAAA de la section réponse : (type, rdata, ttl).
    pub addrs: Vec<(u16, Vec<u8>, u32)>,
    pub truncated: bool,
}

pub fn response_info(buf: &[u8]) -> Option<RespInfo> {
    if buf.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let ns = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        let (_, p) = read_name(buf, pos)?;
        pos = p + 4;
    }
    let mut info = RespInfo {
        rcode: (flags & 0xF) as u8,
        truncated: flags & 0x0200 != 0,
        ..Default::default()
    };
    let mut min_ttl: Option<u32> = None;
    for i in 0..(an + ns) {
        let (_, np) = read_name(buf, pos)?;
        if np + 10 > buf.len() {
            return None;
        }
        let t = u16::from_be_bytes([buf[np], buf[np + 1]]);
        let ttl = u32::from_be_bytes([buf[np + 4], buf[np + 5], buf[np + 6], buf[np + 7]]);
        let rdlen = u16::from_be_bytes([buf[np + 8], buf[np + 9]]) as usize;
        let rd = buf.get(np + 10..np + 10 + rdlen)?;
        if i < an {
            min_ttl = Some(min_ttl.map_or(ttl, |m| m.min(ttl)));
            if (t == T_A && rdlen == 4) || (t == T_AAAA && rdlen == 16) {
                info.addrs.push((t, rd.to_vec(), ttl));
            }
        } else if t == T_SOA && an == 0 {
            min_ttl = Some(min_ttl.map_or(ttl, |m| m.min(ttl)));
        }
        pos = np + 10 + rdlen;
    }
    info.ttl = min_ttl;
    Some(info)
}

// --- Fabrication d'enregistrements ---

pub fn rr_a(name: &str, ttl: u32, ip: Ipv4Addr) -> Rr {
    Rr { name: name.into(), rtype: T_A, ttl, rdata: ip.octets().to_vec() }
}

pub fn rr_aaaa(name: &str, ttl: u32, ip: Ipv6Addr) -> Rr {
    Rr { name: name.into(), rtype: T_AAAA, ttl, rdata: ip.octets().to_vec() }
}

pub fn rr_name(name: &str, rtype: u16, ttl: u32, target: &str) -> Rr {
    let mut rdata = Vec::new();
    write_name(&mut rdata, target);
    Rr { name: name.into(), rtype, ttl, rdata }
}

pub fn rr_soa(zone: &str, ttl: u32, serial: u32) -> Rr {
    let mut rdata = Vec::new();
    write_name(&mut rdata, &format!("ns.{zone}"));
    write_name(&mut rdata, &format!("hostmaster.{zone}"));
    for v in [serial, 3600, 600, 86400, 60] {
        rdata.extend_from_slice(&v.to_be_bytes());
    }
    Rr { name: zone.into(), rtype: T_SOA, ttl, rdata }
}

fn norm_target(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Construit un enregistrement à partir de sa représentation texte.
/// `name` est le nom complet (FQDN sans point final).
pub fn parse_record(rtype: &str, name: &str, value: &str, ttl: u32) -> Result<Rr, String> {
    let value = value.trim();
    let t = type_from_name(rtype).ok_or_else(|| format!("type inconnu : {rtype}"))?;
    match t {
        T_A => {
            let ip: Ipv4Addr = value.parse().map_err(|_| "adresse IPv4 invalide".to_string())?;
            Ok(rr_a(name, ttl, ip))
        }
        T_AAAA => {
            let ip: Ipv6Addr = value.parse().map_err(|_| "adresse IPv6 invalide".to_string())?;
            Ok(rr_aaaa(name, ttl, ip))
        }
        T_CNAME | T_NS | T_PTR => {
            let target = norm_target(value);
            if target.is_empty() {
                return Err("la cible est vide".into());
            }
            Ok(rr_name(name, t, ttl, &target))
        }
        T_MX => {
            let mut it = value.split_whitespace();
            let pref: u16 = it.next().and_then(|v| v.parse().ok()).ok_or("format attendu : « 10 mail.exemple.lan »")?;
            let host = norm_target(it.next().ok_or("hôte manquant")?);
            let mut rdata = pref.to_be_bytes().to_vec();
            write_name(&mut rdata, &host);
            Ok(Rr { name: name.into(), rtype: t, ttl, rdata })
        }
        T_TXT => {
            let text = value.trim_matches('"');
            let mut rdata = Vec::new();
            if text.is_empty() {
                rdata.push(0);
            }
            for chunk in text.as_bytes().chunks(255) {
                rdata.push(chunk.len() as u8);
                rdata.extend_from_slice(chunk);
            }
            Ok(Rr { name: name.into(), rtype: t, ttl, rdata })
        }
        T_SRV => {
            let p: Vec<&str> = value.split_whitespace().collect();
            if p.len() != 4 {
                return Err("format attendu : « priorité poids port cible »".into());
            }
            let mut rdata = Vec::new();
            for v in &p[..3] {
                let n: u16 = v.parse().map_err(|_| "nombre invalide".to_string())?;
                rdata.extend_from_slice(&n.to_be_bytes());
            }
            write_name(&mut rdata, &norm_target(p[3]));
            Ok(Rr { name: name.into(), rtype: t, ttl, rdata })
        }
        T_CAA => {
            let p: Vec<&str> = value.splitn(3, char::is_whitespace).collect();
            if p.len() != 3 {
                return Err("format attendu : « 0 issue \"letsencrypt.org\" »".into());
            }
            let flags: u8 = p[0].parse().map_err(|_| "drapeau invalide".to_string())?;
            let tag = p[1];
            let val = p[2].trim().trim_matches('"');
            let mut rdata = vec![flags, tag.len() as u8];
            rdata.extend_from_slice(tag.as_bytes());
            rdata.extend_from_slice(val.as_bytes());
            Ok(Rr { name: name.into(), rtype: t, ttl, rdata })
        }
        _ => Err("type non géré".into()),
    }
}

pub fn reverse_name_v4(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}
