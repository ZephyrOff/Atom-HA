//! Analyse des listes de filtrage (syntaxe AdGuard, hosts, liste de domaines)
//! et évaluation d'un nom de domaine.

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

struct RegexRule {
    re: Regex,
    allow: bool,
    important: bool,
    rw: Option<Rw>,
    raw: String,
}

#[derive(Default)]
pub struct ParsedList {
    pub id: String,
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

impl ParsedList {
    pub fn parse(id: &str, name: &str, text: &str) -> ParsedList {
        let mut l = ParsedList { id: id.into(), name: name.into(), ..Default::default() };
        for line in text.lines() {
            l.add_line(line.trim());
        }
        l
    }

    fn add_line(&mut self, line: &str) {
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            return;
        }
        if line.starts_with('#') {
            // commentaire, sauf règles cosmétiques qu'on ignore aussi
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
        // séparation pattern / modificateurs
        let split_at = if rest.starts_with('/') {
            rest.rfind("/$").map(|i| i + 1)
        } else {
            rest.rfind('$')
        };
        let (pattern, mods) = match split_at {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        let mut important = false;
        let mut rewrite: Option<Rw> = None;
        for m in mods.split(',').map(str::trim).filter(|m| !m.is_empty()) {
            if m == "important" {
                important = true;
            } else if let Some(v) = m.strip_prefix("dnsrewrite=") {
                match parse_rewrite(v) {
                    Some(r) => rewrite = Some(r),
                    None => {
                        self.unsupported += 1;
                        return;
                    }
                }
            } else {
                // client, dnstype, denyallow, badfilter... non gérés
                self.unsupported += 1;
                return;
            }
        }
        if pattern.is_empty() {
            return;
        }
        // expression régulière
        if pattern.len() > 2 && pattern.starts_with('/') && pattern.ends_with('/') {
            if let Ok(re) = RegexBuilder::new(&pattern[1..pattern.len() - 1]).size_limit(1 << 20).build() {
                self.regexes.push(RegexRule { re, allow, important, rw: rewrite, raw: line.to_string() });
                self.count += 1;
            } else {
                self.unsupported += 1;
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
            self.unsupported += 1;
            return;
        }
        let plain = is_domainish(&body);
        let wildcard = !plain && body.chars().all(|c| c.is_ascii_alphanumeric() || "-_.*".contains(c));
        if !plain && !wildcard {
            self.unsupported += 1;
            return;
        }
        if plain && (anchor_sub || (!anchor_exact && body.contains('.'))) {
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
            if let Some(rw) = rewrite {
                self.rw_exact.insert(body, rw);
            } else if allow {
                self.allow_exact.insert(body);
            } else {
                self.block_exact.insert(body);
            }
            self.count += 1;
        } else if let Some(re) = wildcard_regex(&body, anchor_sub || anchor_exact, caret_end || anchor_exact, anchor_sub) {
            self.regexes.push(RegexRule { re, allow, important, rw: rewrite, raw: line.to_string() });
            self.count += 1;
        } else {
            self.unsupported += 1;
        }
    }

    fn lookup(&self, host: &str) -> Matches {
        let mut m = Matches::default();
        if self.block_exact.contains(host) {
            m.block = Some(format!("{host}"));
        }
        if self.allow_exact.contains(host) {
            m.allow = Some(format!("@@|{host}^"));
        }
        if let Some(rw) = self.rw_exact.get(host) {
            m.rewrite = Some((rw.clone(), format!("|{host}^$dnsrewrite={}", rw.describe())));
        }
        let mut cur = host;
        loop {
            if let Some(imp) = self.block_suffix.get(cur) {
                let rule = format!("||{cur}^");
                if *imp {
                    m.important = Some(format!("{rule}$important"));
                } else if m.block.is_none() {
                    m.block = Some(rule);
                }
            }
            if m.allow.is_none() && self.allow_suffix.contains(cur) {
                m.allow = Some(format!("@@||{cur}^"));
            }
            if m.rewrite.is_none() {
                if let Some(rw) = self.rw_suffix.get(cur) {
                    m.rewrite = Some((rw.clone(), format!("||{cur}^$dnsrewrite={}", rw.describe())));
                }
            }
            match cur.find('.') {
                Some(i) => cur = &cur[i + 1..],
                None => break,
            }
        }
        for r in &self.regexes {
            if r.re.is_match(host) {
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

/// Évalue un nom contre les listes (la première est prioritaire).
/// Priorité : blocage important > exception > réécriture > blocage.
pub fn check(lists: &[std::sync::Arc<ParsedList>], host: &str) -> Option<Hit> {
    let mut allow = None;
    let mut rewrite = None;
    let mut block = None;
    for l in lists {
        let m = l.lookup(host);
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
        vec![Arc::new(ParsedList::parse("t", "test", text))]
    }

    #[test]
    fn suffix_and_allow() {
        let l = one("||tracker.exemple.com^\n@@||cdn.tracker.exemple.com^\n");
        assert!(matches!(check(&l, "www.tracker.exemple.com").unwrap().kind, HitKind::Block));
        assert!(matches!(check(&l, "cdn.tracker.exemple.com").unwrap().kind, HitKind::Allow));
        assert!(check(&l, "exemple.com").is_none());
    }

    #[test]
    fn hosts_and_domains() {
        let l = one("0.0.0.0 ads.example.net\nplain.example.org\n# note\n");
        assert!(check(&l, "ads.example.net").is_some());
        assert!(check(&l, "x.ads.example.net").is_none());
        assert!(check(&l, "a.plain.example.org").is_some());
    }

    #[test]
    fn regex_wildcard_rewrite() {
        let l = one("/^ad[0-9]+\\.reseau\\.net$/\n||pub*.site.fr^\n||jeu.lan^$dnsrewrite=10.0.0.5\n");
        assert!(check(&l, "ad42.reseau.net").is_some());
        assert!(check(&l, "pub3.site.fr").is_some());
        match check(&l, "jeu.lan").unwrap().kind {
            HitKind::Rewrite(Rw::Ip(ip)) => assert_eq!(ip.to_string(), "10.0.0.5"),
            _ => panic!(),
        }
    }

    #[test]
    fn important_beats_allow() {
        let l = one("@@||a.com^\n||a.com^$important\n");
        assert!(matches!(check(&l, "a.com").unwrap().kind, HitKind::Block));
    }
}
