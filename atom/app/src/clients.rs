//! Identification des clients (adresses ou plages CIDR) et portée des configurations.

use std::net::IpAddr;

#[derive(Clone, Debug)]
pub struct Cidr {
    addr: u128,
    prefix: u8,
    v4: bool,
}

fn parts(ip: IpAddr) -> (u128, u8, bool) {
    match ip {
        IpAddr::V4(v) => (u32::from(v) as u128, 32, true),
        IpAddr::V6(v) => (u128::from(v), 128, false),
    }
}

fn mask(a: u128, prefix: u8, max: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        let shift = (max - prefix) as u32;
        (a >> shift) << shift
    }
}

impl Cidr {
    /// Accepte « 192.168.1.20 », « 192.168.1.0/24 », « fd00::/64 ».
    pub fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        let (ip, pre) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let ip: IpAddr = ip.trim().parse().ok()?;
        let (addr, max, v4) = parts(ip);
        let prefix = match pre {
            Some(p) => p.trim().parse::<u8>().ok()?,
            None => max,
        };
        if prefix > max {
            return None;
        }
        Some(Cidr { addr: mask(addr, prefix, max), prefix, v4 })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let (a, max, v4) = parts(ip);
        v4 == self.v4 && mask(a, self.prefix, max) == self.addr
    }
}

#[derive(Clone, Debug, Default)]
pub struct ClientSet(Vec<Cidr>);

impl ClientSet {
    pub fn parse<S: AsRef<str>>(ids: &[S]) -> Self {
        Self(ids.iter().filter_map(|s| Cidr::parse(s.as_ref())).collect())
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }

    pub fn contains_str(&self, s: &str) -> bool {
        s.parse::<IpAddr>().map_or(false, |ip| self.contains(ip))
    }

    /// Longueur de préfixe de la correspondance la plus précise, s'il y en a une.
    pub fn specificity(&self, ip: IpAddr) -> Option<u8> {
        self.0.iter().filter(|c| c.contains(ip)).map(|c| c.prefix).max()
    }
}

/// Qui est ce client pour la configuration : l'id du client enregistré et celui de son groupe.
#[derive(Clone, Debug, Default)]
pub struct Identity {
    pub client: Option<String>,
    pub group: Option<String>,
}

impl Identity {
    /// Une configuration sans portée vaut pour tout le monde.
    pub fn in_scope(&self, clients: &[String], groups: &[String]) -> bool {
        if clients.is_empty() && groups.is_empty() {
            return true;
        }
        self.client.as_ref().map_or(false, |c| clients.contains(c))
            || self.group.as_ref().map_or(false, |g| groups.contains(g))
    }
}

/// Adresse locale (réseau privé, boucle locale, lien local, ULA).
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified(),
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_loopback() || v.is_unspecified() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matching() {
        let s = ClientSet::parse(&["192.168.1.20", "10.0.0.0/8", "fd00::/64"]);
        assert!(s.contains("192.168.1.20".parse().unwrap()));
        assert!(!s.contains("192.168.1.21".parse().unwrap()));
        assert!(s.contains("10.9.8.7".parse().unwrap()));
        assert!(s.contains("fd00::5".parse().unwrap()));
        assert!(!s.contains("fd01::5".parse().unwrap()));
        assert_eq!(s.specificity("192.168.1.20".parse().unwrap()), Some(32));
        assert!(Cidr::parse("1.2.3.4/33").is_none());
    }

    #[test]
    fn private_ranges() {
        assert!(is_private(&"192.168.0.1".parse().unwrap()));
        assert!(is_private(&"fd12::1".parse().unwrap()));
        assert!(!is_private(&"1.1.1.1".parse().unwrap()));
    }
}
