//! Types de configuration répliquée et leur validation.

use crate::dnswire;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Settings {
    pub filtering_enabled: bool,
    pub rewrites_enabled: bool,
    /// null_ip | nxdomain | refused
    pub block_mode: String,
    /// ordered | parallel
    pub upstream_mode: String,
    pub cache_enabled: bool,
    pub cache_size: usize,
    pub timeout_ms: u64,
    pub pause_until: Option<u64>,
    pub log_enabled: bool,
    /// Demande aux upstreams de valider DNSSEC (bit AD/DO) et signale le résultat dans le journal.
    pub dnssec: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            filtering_enabled: true,
            rewrites_enabled: true,
            block_mode: "null_ip".into(),
            upstream_mode: "ordered".into(),
            cache_enabled: true,
            cache_size: 20000,
            timeout_ms: 3000,
            pause_until: None,
            log_enabled: true,
            dnssec: false,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct UpstreamCfg {
    pub name: String,
    pub address: String,
    pub bootstrap: String,
    pub enabled: bool,
    pub order: f64,
    pub domains: Vec<String>,
    /// Upstream de secours : interrogé seulement quand les autres n'ont pas répondu.
    pub backup: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct ListCfg {
    pub name: String,
    /// url | inline
    pub kind: String,
    pub url: String,
    pub content: String,
    pub enabled: bool,
    pub interval_hours: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct RewriteCfg {
    pub domain: String,
    pub answer: String,
    pub enabled: bool,
    pub expires_at: Option<u64>,
    /// Ids de clients concernés (vide avec `groups` vide = tout le monde).
    pub clients: Vec<String>,
    pub groups: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct ZoneCfg {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct RecordCfg {
    pub zone: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub name: String,
    pub value: String,
    pub ttl: u32,
    pub ptr: bool,
    pub enabled: bool,
    pub clients: Vec<String>,
    pub groups: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct ClientCfg {
    pub name: String,
    /// Adresses IP ou plages CIDR.
    pub ids: Vec<String>,
    pub group: String,
    pub notes: String,
    pub block_internet: bool,
    pub block_lan: bool,
    pub block_until: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct GroupCfg {
    pub name: String,
    pub description: String,
    pub block_internet: bool,
    pub block_lan: bool,
    pub block_until: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct CustomRules {
    pub text: String,
}

/// Domaine autorisé temporairement : le filtrage est ignoré jusqu'à `until` (ms depuis 1970).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct TempAllow {
    pub domain: String,
    pub until: u64,
    pub note: String,
}

pub const COLLECTIONS: &[&str] = &["settings", "upstreams", "lists", "rewrites", "zones", "records", "rules", "clients", "groups", "tempallow"];

pub fn norm_domain(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn valid_hostname(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

/// FQDN d'un enregistrement dans une zone.
pub fn record_fqdn(zone: &str, name: &str) -> String {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if n.is_empty() || n == "@" {
        zone.to_string()
    } else if n.ends_with(&format!(".{zone}")) || n == zone {
        n
    } else {
        format!("{n}.{zone}")
    }
}

/// Valide et normalise une valeur avant de l'écrire dans le magasin.
pub fn validate(col: &str, v: Value) -> Result<Value, String> {
    fn de<T: for<'a> Deserialize<'a>>(v: Value) -> Result<T, String> {
        serde_json::from_value(v).map_err(|e| format!("données invalides : {e}"))
    }
    fn ser<T: Serialize>(t: &T) -> Value {
        serde_json::to_value(t).unwrap_or(Value::Null)
    }
    match col {
        "settings" => {
            let mut s: Settings = de(v)?;
            if !["null_ip", "nxdomain", "refused"].contains(&s.block_mode.as_str()) {
                return Err("mode de blocage inconnu".into());
            }
            if !["ordered", "parallel"].contains(&s.upstream_mode.as_str()) {
                return Err("mode upstream inconnu".into());
            }
            s.timeout_ms = s.timeout_ms.clamp(200, 20000);
            s.cache_size = s.cache_size.clamp(100, 1_000_000);
            Ok(ser(&s))
        }
        "upstreams" => {
            let mut u: UpstreamCfg = de(v)?;
            u.name = u.name.trim().to_string();
            u.address = u.address.trim().to_string();
            if u.address.is_empty() {
                return Err("l'adresse est obligatoire".into());
            }
            crate::upstream::parse_address(&u.address, &u.bootstrap).map_err(|e| e.to_string())?;
            if u.name.is_empty() {
                u.name = u.address.clone();
            }
            u.domains = u.domains.iter().map(|d| norm_domain(d)).filter(|d| !d.is_empty()).collect();
            Ok(ser(&u))
        }
        "lists" => {
            let mut l: ListCfg = de(v)?;
            l.name = l.name.trim().to_string();
            if l.kind != "url" && l.kind != "inline" {
                return Err("type de liste inconnu".into());
            }
            if l.kind == "url" && !(l.url.starts_with("http://") || l.url.starts_with("https://")) {
                return Err("l'URL doit commencer par http:// ou https://".into());
            }
            if l.name.is_empty() {
                l.name = if l.kind == "url" { l.url.clone() } else { "Liste locale".into() };
            }
            if l.interval_hours == 0 {
                l.interval_hours = 12;
            }
            Ok(ser(&l))
        }
        "rewrites" => {
            let mut r: RewriteCfg = de(v)?;
            r.domain = norm_domain(&r.domain);
            r.answer = r.answer.trim().to_string();
            let base = r.domain.strip_prefix("*.").unwrap_or(&r.domain);
            if !valid_hostname(base) {
                return Err("domaine invalide".into());
            }
            if r.answer.parse::<std::net::IpAddr>().is_err() {
                let a = norm_domain(&r.answer);
                if !valid_hostname(&a) {
                    return Err("la réponse doit être une adresse IP ou un nom de domaine".into());
                }
                r.answer = a;
            }
            Ok(ser(&r))
        }
        "zones" => {
            let mut z: ZoneCfg = de(v)?;
            z.name = norm_domain(&z.name);
            if !valid_hostname(&z.name) {
                return Err("nom de zone invalide".into());
            }
            Ok(ser(&z))
        }
        "records" => {
            let mut r: RecordCfg = de(v)?;
            r.zone = norm_domain(&r.zone);
            r.rtype = r.rtype.to_ascii_uppercase();
            if r.zone.is_empty() {
                return Err("zone manquante".into());
            }
            if r.ttl == 0 {
                r.ttl = 300;
            }
            let fq = record_fqdn(&r.zone, &r.name);
            let base = fq.strip_prefix("*.").unwrap_or(&fq);
            if !valid_hostname(base) {
                return Err("nom invalide".into());
            }
            dnswire::parse_record(&r.rtype, &fq, &r.value, r.ttl)?;
            if r.ptr && r.rtype != "A" {
                r.ptr = false;
            }
            Ok(ser(&r))
        }
        "rules" => {
            let r: CustomRules = de(v)?;
            Ok(ser(&r))
        }
        "clients" => {
            let mut c: ClientCfg = de(v)?;
            c.name = c.name.trim().to_string();
            c.ids = c.ids.iter().map(|i| i.trim().to_string()).filter(|i| !i.is_empty()).collect();
            if c.name.is_empty() {
                return Err("le nom est obligatoire".into());
            }
            if c.ids.is_empty() {
                return Err("au moins une adresse IP ou plage CIDR est nécessaire".into());
            }
            for i in &c.ids {
                if crate::clients::Cidr::parse(i).is_none() {
                    return Err(format!("« {i} » n'est pas une adresse IP ni une plage CIDR valide"));
                }
            }
            Ok(ser(&c))
        }
        "tempallow" => {
            let mut t: TempAllow = de(v)?;
            t.domain = norm_domain(&t.domain);
            if !valid_hostname(&t.domain) {
                return Err("domaine invalide".into());
            }
            if t.until == 0 {
                return Err("la date de fin est obligatoire".into());
            }
            Ok(ser(&t))
        }
        "groups" => {
            let mut g: GroupCfg = de(v)?;
            g.name = g.name.trim().to_string();
            if g.name.is_empty() {
                return Err("le nom est obligatoire".into());
            }
            Ok(ser(&g))
        }
        _ => Err("collection inconnue".into()),
    }
}

pub fn seed_defaults(store: &crate::store::Store) {
    store.seed("settings", "main", json!(Settings::default()));
    let ups = [
        ("cloudflare", "Cloudflare (DoH)", "https://cloudflare-dns.com/dns-query", "1.1.1.1", 1.0),
        ("cloudflare-dot", "Cloudflare (DoT)", "tls://one.one.one.one", "1.1.1.1", 2.0),
        ("google", "Google (UDP)", "8.8.8.8", "", 3.0),
    ];
    for (id, name, addr, boot, order) in ups {
        store.seed(
            "upstreams",
            id,
            json!(UpstreamCfg {
                name: name.into(),
                address: addr.into(),
                bootstrap: boot.into(),
                enabled: true,
                order,
                domains: vec![],
                backup: false,
            }),
        );
    }
    store.seed(
        "lists",
        "adguard-dns",
        json!(ListCfg {
            name: "AdGuard DNS filter".into(),
            kind: "url".into(),
            url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt".into(),
            content: String::new(),
            enabled: true,
            interval_hours: 12,
        }),
    );
}
