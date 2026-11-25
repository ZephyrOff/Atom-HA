//! Analyse des listes de filtrage (syntaxe AdGuard, hosts, liste de domaines)
//! et évaluation d'un nom de domaine.
//!
//! Modificateurs gérés : `important`, `dnsrewrite`, `client`, `dnstype`, `denyallow`, `badfilter`.

use crate::clients::Cidr;
use crate::dnswire;
use regex::{Regex, RegexBuilder};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq)]
pub enum Rw {
    Ip(IpAddr),
    Cname(String),
    NxDomain,
    Refused,
}

impl Rw {
    pub fn describe(&self) -> String {
        match self {
            Rw::Ip(ip) => ip.to_string(),
            Rw::Cname(c) => c.clone(),
            Rw::NxDomain => "NXDOMAIN".into(),
            Rw::Refused => "REFUSED".into(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum HitKind {
    Block,
    Allow,
    Rewrite(Rw),
}

#[derive(Clone, Debug)]
pub struct Hit {
    pub kind: HitKind,
    pub rule: String,
    pub list: String,
}

/// Contexte de la requête, pour les règles qui dépendent du client ou du type.
pub struct Ctx<'a> {
    pub ip: IpAddr,
    pub client_name: Option<&'a str>,
    pub qtype: u16,
}

struct RegexRule {
    re: Regex,
    allow: bool,
    important: bool,
    rw: Option<Rw>,
    raw: String,
}

enum Matcher {
    Suffix(String),
    Exact(String),
    Re(Regex),
}

enum ClientSpec {
    Net(Cidr),
    Name(String),
}

#[derive(Default)]
struct ClientCond {
    include: Vec<ClientSpec>,
    exclude: Vec<ClientSpec>,
}

#[derive(Default)]
struct TypeCond {
    include: Vec<u16>,
    exclude: Vec<u16>,
}

/// Règle qui dépend du client, du type de requête, ou qui exclut des domaines.
struct CondRule {
    m: Matcher,
    allow: bool,
    important: bool,
    rw: Option<Rw>,
    clients: Option<ClientCond>,
    types: Option<TypeCond>,
    denyallow: Vec<String>,
    raw: String,
}

fn domain_matches(d: &str, host: &str) -> bool {
    host == d || (host.len() > d.len() && host.ends_with(d) && host.as_bytes()[host.len() - d.len() - 1] == b'.')
}

impl ClientCond {
    fn matches(&self, ctx: &Ctx) -> bool {
        let hit = |s: &ClientSpec| match s {
            ClientSpec::Net(c) => c.contains(ctx.ip),
            ClientSpec::Name(n) => ctx.client_name.map_or(false, |c| c.eq_ignore_ascii_case(n)),
        };
        (self.include.is_empty() || self.include.iter().any(hit)) && !self.exclude.iter().any(hit)
    }
}

impl TypeCond {
    fn matches(&self, t: u16) -> bool {
        (self.include.is_empty() || self.include.contains(&t)) && !self.exclude.contains(&t)
    }
}

impl CondRule {
    fn applies(&self, host: &str, ctx: &Ctx) -> bool {
        let m = match &self.m {
            Matcher::Suffix(d) => domain_matches(d, host),
            Matcher::Exact(d) => host == d,
            Matcher::Re(r) => r.is_match(host),
        };
        m && self.clients.as_ref().map_or(true, |c| c.matches(ctx))
            && self.types.as_ref().map_or(true, |t| t.matches(ctx.qtype))
            && !self.denyallow.iter().any(|d| domain_matches(d, host))
    }
}

#[derive(Default)]
pub struct ParsedList {
    pub name: String,
    pub count: usize,
    pub unsupported: usize,
    block_suffix: HashMap<String, bool>, // valeur = important
    allow_suffix: HashSet<String>,
    block_exact: HashSet<String>,
    allow_exact: HashSet<String>,
    rw_suffix: HashMap<String, Rw>,
    rw_exact: HashMap<String, Rw>,
    regexes: Vec<RegexRule>,
    conds: Vec<CondRule>,
    /// Règles désactivées par `$badfilter` dans cette liste (texte sans le modificateur).
    pub bad: HashSet<String>,
}

fn is_domainish(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !s.starts_with('.')
        && !s.ends_with('.')
        && !s.contains("..")
}

fn is_null_ip(ip: &IpAddr) -> bool {
    ip.is_unspecified() || ip.to_string() == "127.0.0.1" || ip.to_string() == "::1"
}

fn wildcard_regex(body: &str, anchor_start: bool, anchor_end: bool, subdomains: bool) -> Option<Regex> {
    let mut p = String::new();
    if anchor_start {
        if subdomains {
            p.push_str("(?:^|\\.)");
        } else {
            p.push('^');
        }
    }
    for part in body.split('*').enumerate() {
        if part.0 > 0 {
            p.push_str(".*");
        }
        p.push_str(&regex::escape(part.1));
    }
    if anchor_end {
        p.push('$');
    }
    RegexBuilder::new(&p).case_insensitive(true).size_limit(1 << 20).build().ok()
}

fn parse_rewrite(v: &str) -> Option<Rw> {
    let v = v.trim();
    if v.eq_ignore_ascii_case("NXDOMAIN") {
        return Some(Rw::NxDomain);
    }
    if v.eq_ignore_ascii_case("REFUSED") {
        return Some(Rw::Refused);
    }
    // forme « NOERROR;A;1.2.3.4 »
    let v = if v.to_ascii_uppercase().starts_with("NOERROR;") {
        v.rsplit(';').next().unwrap_or(v)
    } else {
        v
    };
    if let Ok(ip) = v.parse::<IpAddr>() {
        return Some(Rw::Ip(ip));
    }
    if is_domainish(v) {
        return Some(Rw::Cname(v.to_ascii_lowercase()));
    }
    None
}

/// Sépare « motif$modificateurs ».
fn split_mods(rest: &str) -> (&str, &str) {
    let at = if rest.starts_with('/') { rest.rfind("/$").map(|i| i + 1) } else { rest.rfind('$') };
    match at {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    }
}

/// Si la ligne porte `$badfilter`, retourne le texte de la règle qu'elle désactive.
fn badfilter_target(line: &str) -> Option<String> {
    let (allow_prefix, rest) = match line.strip_prefix("@@") {
        Some(r) => ("@@", r),
        None => ("", line),
    };
    let (pattern, mods) = split_mods(rest);
    if mods.is_empty() {
        return None;
    }
    let parts: Vec<&str> = mods.split(',').map(str::trim).filter(|m| !m.is_empty()).collect();
    if !parts.contains(&"badfilter") {
        return None;
    }
    let others: Vec<&str> = parts.into_iter().filter(|m| *m != "badfilter").collect();
    Some(if others.is_empty() { format!("{allow_prefix}{pattern}") } else { format!("{allow_prefix}{pattern}${}", others.join(",")) })
}

fn parse_client_cond(v: &str) -> Option<ClientCond> {
    let mut c = ClientCond::default();
    for raw in v.split('|') {
        let raw = raw.trim();
        let (neg, item) = match raw.strip_prefix('~') {
            Some(r) => (true, r.trim()),
            None => (false, raw),
        };
        if item.is_empty() {
            return None;
        }
        let quoted = (item.starts_with('\'') && item.ends_with('\'') && item.len() >= 2) || (item.starts_with('"') && item.ends_with('"') && item.len() >= 2);
        let spec = if quoted {
            ClientSpec::Name(item[1..item.len() - 1].to_string())
        } else if let Some(c) = Cidr::parse(item) {
            ClientSpec::Net(c)
        } else {
            ClientSpec::Name(item.to_string())
        };
        if neg {
            c.exclude.push(spec);
        } else {
            c.include.push(spec);
        }
    }
    Some(c)
}

fn parse_type_cond(v: &str) -> Option<TypeCond> {
    let mut c = TypeCond::default();
    for raw in v.split('|') {
        let raw = raw.trim();
        let (neg, item) = match raw.strip_prefix('~') {
            Some(r) => (true, r.trim()),
            None => (false, raw),
        };
        let t = dnswire::type_from_name(item).or_else(|| match item.to_ascii_uppercase().as_str() {
            "HTTPS" => Some(65),
            "SVCB" => Some(64),
            "ANY" => Some(255),
            _ => None,
        })?;
        if neg {
            c.exclude.push(t);
        } else {
            c.include.push(t);
        }
    }
    Some(c)
}

impl ParsedList {
    /// Analyse une liste. Les règles désactivées par `$badfilter` dans cette même liste sont ignorées ;
    /// celles des autres listes le sont à l'évaluation (voir `check`).
    pub fn parse(name: &str, text: &str) -> ParsedList {
        let mut l = ParsedList { name: name.into(), ..Default::default() };
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        for line in &lines {
            if let Some(t) = badfilter_target(line) {
                l.bad.insert(t);
            }
        }
        for line in lines {
            if badfilter_target(line).is_some() || l.bad.contains(line) {
                continue;
            }
            l.add_line(line);
        }
        l
    }

    fn add_line(&mut self, line: &str) {
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            return;
        }
        if line.starts_with('#') {
            return;
        }
        if line.contains("##") || line.contains("#@#") || line.contains("#?#") || line.contains("#$#") {
            return;
        }
        // format hosts : « IP nom [nom...] »
        let mut parts = line.split_whitespace();
        if let Some(first) = parts.next() {
            if let Ok(ip) = first.parse::<IpAddr>() {
                for h in parts {
                    if h.starts_with('#') {
                        break;
                    }
                    let h = h.to_ascii_lowercase();
                    if !is_domainish(&h) || h == "localhost" {
                        continue;
                    }
                    if is_null_ip(&ip) {
                        self.block_exact.insert(h);
                    } else {
                        self.rw_exact.insert(h, Rw::Ip(ip));
                    }
                    self.count += 1;
                }
                return;
            }
        }
        // liste de domaines nus
        if is_domainish(line) && line.contains('.') {
            self.block_suffix.entry(line.to_ascii_lowercase()).or_insert(false);
            self.count += 1;
            return;
        }
        self.add_adguard_rule(line);
    }

    fn add_adguard_rule(&mut self, line: &str) {
        let (allow, rest) = match line.strip_prefix("@@") {
            Some(r) => (true, r),
            None => (false, line),
        };
        let (pattern, mods) = split_mods(rest);
        let mut important = false;
        let mut rewrite: Option<Rw> = None;
        let mut clients: Option<ClientCond> = None;
        let mut types: Option<TypeCond> = None;
        let mut denyallow: Vec<String> = Vec::new();
        for m in mods.split(',').map(str::trim).filter(|m| !m.is_empty()) {
            if m == "important" {
                important = true;
            } else if let Some(v) = m.strip_prefix("dnsrewrite=") {
                match parse_rewrite(v) {
                    Some(r) => rewrite = Some(r),
                    None => return self.reject(),
                }
            } else if let Some(v) = m.strip_prefix("client=") {
                match parse_client_cond(v) {
                    Some(c) => clients = Some(c),
                    None => return self.reject(),
                }
            } else if let Some(v) = m.strip_prefix("dnstype=") {
                match parse_type_cond(v) {
                    Some(c) => types = Some(c),
                    None => return self.reject(),
                }
            } else if let Some(v) = m.strip_prefix("denyallow=") {
                let ds: Vec<String> = v.split('|').map(|d| d.trim().to_ascii_lowercase()).collect();
                if ds.iter().any(|d| !is_domainish(d)) {
                    return self.reject();
                }
                denyallow = ds;
            } else {
                return self.reject();
            }
        }
        if pattern.is_empty() {
            return;
        }
        let conditional = clients.is_some() || types.is_some() || !denyallow.is_empty();
        let mut push_cond = |this: &mut ParsedList, m: Matcher| {
            this.conds.push(CondRule { m, allow, important, rw: rewrite.clone(), clients: clients.take(), types: types.take(), denyallow: denyallow.clone(), raw: line.to_string() });
            this.count += 1;
        };
        // expression régulière
        if pattern.len() > 2 && pattern.starts_with('/') && pattern.ends_with('/') {
            match RegexBuilder::new(&pattern[1..pattern.len() - 1]).size_limit(1 << 20).build() {
                Ok(re) => {
                    if conditional {
                        push_cond(self, Matcher::Re(re));
                    } else {
                        self.regexes.push(RegexRule { re, allow, important, rw: rewrite, raw: line.to_string() });
                        self.count += 1;
                    }
                }
                Err(_) => self.unsupported += 1,
            }
            return;
        }
        let (anchor_sub, anchor_exact, body) = if let Some(b) = pattern.strip_prefix("||") {
            (true, false, b)
        } else if let Some(b) = pattern.strip_prefix('|') {
            (false, true, b)
        } else {
            (false, false, pattern)
        };
        let body = body.trim_end_matches('|');
        let (body, caret_end) = match body.strip_suffix('^') {
            Some(b) => (b, true),
            None => (body, false),
        };
        let body = body.to_ascii_lowercase();
        if body.is_empty() || body.contains('/') || body.contains(':') || body.contains('^') {
            return self.reject();
        }
        let plain = is_domainish(&body);
        let wildcard = !plain && body.chars().all(|c| c.is_ascii_alphanumeric() || "-_.*".contains(c));
        if !plain && !wildcard {
            return self.reject();
        }
        if plain && (anchor_sub || (!anchor_exact && body.contains('.'))) {
            if conditional {
                push_cond(self, Matcher::Suffix(body));
                return;
            }
            // suffixe : domaine et sous-domaines
            if let Some(rw) = rewrite {
                self.rw_suffix.insert(body, rw);
            } else if allow {
                self.allow_suffix.insert(body);
            } else {
                let e = self.block_suffix.entry(body).or_insert(false);
                *e = *e || important;
            }
            self.count += 1;
        } else if plain && anchor_exact {
            if conditional {
                push_cond(self, Matcher::Exact(body));
                return;
            }
            if let Some(rw) = rewrite {
                self.rw_exact.insert(body, rw);
            } else if allow {
                self.allow_exact.insert(body);
            } else {
                self.block_exact.insert(body);
            }
            self.count += 1;
        } else if let Some(re) = wildcard_regex(&body, anchor_sub || anchor_exact, caret_end || anchor_exact, anchor_sub) {
            if conditional {
                push_cond(self, Matcher::Re(re));
            } else {
                self.regexes.push(RegexRule { re, allow, important, rw: rewrite, raw: line.to_string() });
                self.count += 1;
            }
        } else {
            self.reject();
        }
    }

    fn reject(&mut self) {
        self.unsupported += 1;
    }

    fn lookup(&self, host: &str, ctx: &Ctx, off: &HashSet<String>) -> Matches {
        let mut m = Matches::default();
        let on = |t: &str| !off.contains(t);
        if self.block_exact.contains(host) && on(host) {
            m.block = Some(host.to_string());
        }
        if self.allow_exact.contains(host) && on(&format!("@@|{host}^")) {
            m.allow = Some(format!("@@|{host}^"));
        }
        if let Some(rw) = self.rw_exact.get(host) {
            let t = format!("|{host}^$dnsrewrite={}", rw.describe());
            if on(&t) {
                m.rewrite = Some((rw.clone(), t));
            }
        }
        let mut cur = host;
        loop {
            if let Some(imp) = self.block_suffix.get(cur) {
                let plain = format!("||{cur}^");
                if *imp {
                    let t = format!("{plain}$important");
                    if on(&t) {
                        m.important = Some(t);
                    }
                } else if m.block.is_none() && on(&plain) && on(cur) {
                    m.block = Some(plain);
                }
            }
            if m.allow.is_none() && self.allow_suffix.contains(cur) {
                let t = format!("@@||{cur}^");
                if on(&t) {
                    m.allow = Some(t);
                }
            }
            if m.rewrite.is_none() {
                if let Some(rw) = self.rw_suffix.get(cur) {
                    let t = format!("||{cur}^$dnsrewrite={}", rw.describe());
                    if on(&t) {
                        m.rewrite = Some((rw.clone(), t));
                    }
                }
            }
            match cur.find('.') {
                Some(i) => cur = &cur[i + 1..],
                None => break,
            }
        }
        for r in &self.regexes {
            if r.re.is_match(host) && on(&r.raw) {
                if let Some(rw) = &r.rw {
                    if m.rewrite.is_none() {
                        m.rewrite = Some((rw.clone(), r.raw.clone()));
                    }
                } else if r.allow {
                    if m.allow.is_none() {
                        m.allow = Some(r.raw.clone());
                    }
                } else if r.important {
                    m.important = Some(r.raw.clone());
                } else if m.block.is_none() {
                    m.block = Some(r.raw.clone());
                }
            }
        }
        for r in &self.conds {
            if !r.applies(host, ctx) || !on(&r.raw) {
                continue;
            }
            if let Some(rw) = &r.rw {
                if m.rewrite.is_none() {
                    m.rewrite = Some((rw.clone(), r.raw.clone()));
                }
            } else if r.allow {
                if m.allow.is_none() {
                    m.allow = Some(r.raw.clone());
                }
            } else if r.important {
                m.important = Some(r.raw.clone());
            } else if m.block.is_none() {
                m.block = Some(r.raw.clone());
            }
        }
        m
    }
}

#[derive(Default)]
struct Matches {
    important: Option<String>,
    allow: Option<String>,
    rewrite: Option<(Rw, String)>,
    block: Option<String>,
}

/// Règles désactivées par `$badfilter`, toutes listes confondues.
pub fn disabled_rules(lists: &[std::sync::Arc<ParsedList>]) -> HashSet<String> {
    lists.iter().flat_map(|l| l.bad.iter().cloned()).collect()
}

/// Évalue un nom contre les listes (la première est prioritaire).
/// Priorité : blocage important > exception > réécriture > blocage.
pub fn check(lists: &[std::sync::Arc<ParsedList>], host: &str, ctx: &Ctx, off: &HashSet<String>) -> Option<Hit> {
    let mut allow = None;
    let mut rewrite = None;
    let mut block = None;
    for l in lists {
        let m = l.lookup(host, ctx, off);
        if let Some(r) = m.important {
            return Some(Hit { kind: HitKind::Block, rule: r, list: l.name.clone() });
        }
        if allow.is_none() {
            if let Some(r) = m.allow {
                allow = Some(Hit { kind: HitKind::Allow, rule: r, list: l.name.clone() });
            }
        }
        if rewrite.is_none() {
            if let Some((rw, r)) = m.rewrite {
                rewrite = Some(Hit { kind: HitKind::Rewrite(rw), rule: r, list: l.name.clone() });
            }
        }
        if block.is_none() {
            if let Some(r) = m.block {
                block = Some(Hit { kind: HitKind::Block, rule: r, list: l.name.clone() });
            }
        }
    }
    allow.or(rewrite).or(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn one(text: &str) -> Vec<Arc<ParsedList>> {
        vec![Arc::new(ParsedList::parse("test", text))]
    }

    fn ctx(ip: &str, name: Option<&'static str>, qtype: u16) -> Ctx<'static> {
        Ctx { ip: ip.parse().unwrap(), client_name: name, qtype }
    }

    fn chk(l: &[Arc<ParsedList>], host: &str) -> Option<Hit> {
        check(l, host, &ctx("192.168.1.10", None, 1), &disabled_rules(l))
    }

    #[test]
    fn suffix_and_allow() {
        let l = one("||tracker.exemple.com^\n@@||cdn.tracker.exemple.com^\n");
        assert!(matches!(chk(&l, "www.tracker.exemple.com").unwrap().kind, HitKind::Block));
        assert!(matches!(chk(&l, "cdn.tracker.exemple.com").unwrap().kind, HitKind::Allow));
        assert!(chk(&l, "exemple.com").is_none());
    }

    #[test]
    fn hosts_and_domains() {
        let l = one("0.0.0.0 ads.example.net\nplain.example.org\n# note\n");
        assert!(chk(&l, "ads.example.net").is_some());
        assert!(chk(&l, "x.ads.example.net").is_none());
        assert!(chk(&l, "a.plain.example.org").is_some());
    }

    #[test]
    fn regex_wildcard_rewrite() {
        let l = one("/^ad[0-9]+\\.reseau\\.net$/\n||pub*.site.fr^\n||jeu.lan^$dnsrewrite=10.0.0.5\n");
        assert!(chk(&l, "ad42.reseau.net").is_some());
        assert!(chk(&l, "pub3.site.fr").is_some());
        match chk(&l, "jeu.lan").unwrap().kind {
            HitKind::Rewrite(Rw::Ip(ip)) => assert_eq!(ip.to_string(), "10.0.0.5"),
            _ => panic!(),
        }
    }

    #[test]
    fn important_beats_allow() {
        let l = one("@@||a.com^\n||a.com^$important\n");
        assert!(matches!(chk(&l, "a.com").unwrap().kind, HitKind::Block));
    }

    #[test]
    fn client_modifier() {
        let l = one("||jeux.com^$client=192.168.1.10|'Tablette'\n||video.com^$client=~192.168.1.10\n");
        let r = |ip: &str, n: Option<&'static str>, h: &str| check(&l, h, &ctx(ip, n, 1), &disabled_rules(&l)).is_some();
        assert!(r("192.168.1.10", None, "jeux.com"));
        assert!(r("192.168.1.99", Some("Tablette"), "jeux.com"));
        assert!(!r("192.168.1.99", Some("Autre"), "jeux.com"));
        assert!(!r("192.168.1.10", None, "video.com"));
        assert!(r("192.168.1.11", None, "video.com"));
        assert_eq!(l[0].unsupported, 0);
    }

    #[test]
    fn dnstype_and_denyallow() {
        let l = one("||a.com^$dnstype=AAAA\n||b.com^$denyallow=ok.b.com|x.org\n");
        let r = |h: &str, t: u16| check(&l, h, &ctx("1.1.1.1", None, t), &disabled_rules(&l)).is_some();
        assert!(r("a.com", 28));
        assert!(!r("a.com", 1));
        assert!(r("www.b.com", 1));
        assert!(!r("ok.b.com", 1));
        assert!(!r("sub.ok.b.com", 1));
    }

    #[test]
    fn badfilter_disables_rule_in_other_list() {
        let lists = vec![
            Arc::new(ParsedList::parse("perso", "||pub.exemple.com^$badfilter\n")),
            Arc::new(ParsedList::parse("liste", "||pub.exemple.com^\n||autre.com^\n")),
        ];
        let off = disabled_rules(&lists);
        let c = ctx("1.1.1.1", None, 1);
        assert!(check(&lists, "pub.exemple.com", &c, &off).is_none());
        assert!(check(&lists, "autre.com", &c, &off).is_some());
    }

    #[test]
    fn badfilter_in_same_list() {
        let l = one("||a.com^\n||a.com^$badfilter\n||b.com^\n");
        assert!(chk(&l, "a.com").is_none());
        assert!(chk(&l, "b.com").is_some());
    }
}
