//! Authentification : mot de passe (Argon2id), sessions, protection contre la force brute.

use crate::state::{ct_eq, random_hex, NodeFile};
use crate::store::now_ms;
use argon2::{Algorithm, Argon2, Params, Version};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub const COOKIE: &str = "atom_session";
const IDLE_MS: u64 = 12 * 3600 * 1000;
const ABSOLUTE_MS: u64 = 7 * 24 * 3600 * 1000;
pub const SESSION_MAX_AGE_S: u64 = 7 * 24 * 3600;
const MAX_SESSIONS: usize = 20;

/// Nombre d'échecs tolérés avant un premier blocage, puis blocage doublé à chaque échec.
const FREE_FAILURES: u32 = 4;
const BASE_LOCK_S: u64 = 60;
const MAX_LOCK_S: u64 = 3600;
/// Un compteur d'échecs est oublié après ce délai sans nouvel échec.
const FAIL_DECAY: Duration = Duration::from_secs(3600);
const MAX_TRACKED_IPS: usize = 10_000;

// ---------- mot de passe ----------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PwHash {
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub salt: String,
    pub hash: String,
}

const ARGON_M: u32 = 19 * 1024; // 19 Mio
const ARGON_T: u32 = 2;
const ARGON_P: u32 = 1;

fn derive(pw: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Option<Vec<u8>> {
    let params = Params::new(m, t, p, Some(32)).ok()?;
    let mut out = vec![0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pw.as_bytes(), salt, &mut out)
        .ok()?;
    Some(out)
}

pub fn hash_pw(pw: &str) -> PwHash {
    let salt = random_hex(16);
    let hash = derive(pw, salt.as_bytes(), ARGON_M, ARGON_T, ARGON_P).map(hex::encode).unwrap_or_default();
    PwHash { m: ARGON_M, t: ARGON_T, p: ARGON_P, salt, hash }
}

fn legacy_hash(salt: &str, pw: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(pw.as_bytes());
    hex::encode(h.finalize())
}

/// Vérifie un mot de passe. Retourne aussi `true` pour un ancien hash SHA-256 (migré ensuite).
pub fn verify_pw(n: &NodeFile, pw: &str) -> bool {
    if let Some(h) = &n.pw {
        return derive(pw, h.salt.as_bytes(), h.m, h.t, h.p)
            .map(|d| ct_eq(&hex::encode(d), &h.hash))
            .unwrap_or(false);
    }
    // Calcul factice pour garder un temps de réponse comparable.
    let _ = derive(pw, b"atom-dummy-salt-0", ARGON_M, ARGON_T, ARGON_P);
    !n.pw_hash.is_empty() && ct_eq(&legacy_hash(&n.pw_salt, pw), &n.pw_hash)
}

// ---------- sessions et limiteur ----------

#[derive(Clone, Serialize, Debug)]
pub struct AuthEvent {
    pub ts: u64,
    pub ip: String,
    /// login_ok | login_fail | locked | sync_fail | password_changed | logout
    pub kind: String,
    pub detail: String,
}

struct Session {
    created: u64,
    last_seen: u64,
    ip: String,
}

struct IpState {
    fails: u32,
    last: Instant,
    locked_until: Option<Instant>,
}

#[derive(Serialize)]
pub struct SessionInfo {
    pub ip: String,
    pub created: u64,
    pub last_seen: u64,
    pub current: bool,
}

#[derive(Default)]
pub struct Auth {
    sessions: Mutex<HashMap<String, Session>>,
    ips: Mutex<HashMap<String, IpState>>,
    global: Mutex<VecDeque<Instant>>,
    events: Mutex<VecDeque<AuthEvent>>,
}

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

impl Auth {
    pub fn event(&self, ip: &str, kind: &str, detail: &str) {
        let mut e = self.events.lock();
        e.push_front(AuthEvent { ts: now_ms(), ip: ip.into(), kind: kind.into(), detail: detail.into() });
        e.truncate(100);
    }

    pub fn events(&self) -> Vec<AuthEvent> {
        self.events.lock().iter().cloned().collect()
    }

    // --- limiteur ---

    /// Durée restante de blocage pour cette IP.
    pub fn locked(&self, ip: &str) -> Option<Duration> {
        let g = self.ips.lock();
        let until = g.get(ip)?.locked_until?;
        let now = Instant::now();
        (until > now).then(|| until - now)
    }

    pub fn locked_list(&self) -> Vec<(String, u64)> {
        let now = Instant::now();
        self.ips
            .lock()
            .iter()
            .filter_map(|(ip, s)| s.locked_until.filter(|u| *u > now).map(|u| (ip.clone(), (u - now).as_secs() + 1)))
            .collect()
    }

    /// Enregistre un échec. Retourne la durée de blocage éventuelle.
    pub fn failure(&self, ip: &str) -> Option<Duration> {
        let now = Instant::now();
        {
            let mut g = self.global.lock();
            g.push_back(now);
            while g.front().map_or(false, |t| now.duration_since(*t) > Duration::from_secs(300)) {
                g.pop_front();
            }
        }
        let mut g = self.ips.lock();
        if g.len() >= MAX_TRACKED_IPS {
            g.retain(|_, s| now.duration_since(s.last) < FAIL_DECAY);
            if g.len() >= MAX_TRACKED_IPS {
                g.clear();
            }
        }
        let s = g.entry(ip.to_string()).or_insert(IpState { fails: 0, last: now, locked_until: None });
        if now.duration_since(s.last) > FAIL_DECAY {
            s.fails = 0;
        }
        s.fails += 1;
        s.last = now;
        if s.fails > FREE_FAILURES {
            let exp = (s.fails - FREE_FAILURES - 1).min(10);
            let secs = (BASE_LOCK_S << exp).min(MAX_LOCK_S);
            let d = Duration::from_secs(secs);
            s.locked_until = Some(now + d);
            return Some(d);
        }
        None
    }

    /// Lève le blocage d'une adresse, ou de toutes si `ip` est vide. Retourne le nombre d'adresses débloquées.
    pub fn unlock(&self, ip: &str) -> usize {
        let mut g = self.ips.lock();
        if ip.is_empty() {
            let n = g.len();
            g.clear();
            n
        } else {
            usize::from(g.remove(ip).is_some())
        }
    }

    pub fn success(&self, ip: &str) {
        self.ips.lock().remove(ip);
    }

    /// Délai artificiel imposé aux échecs quand de nombreuses IP échouent en même temps
    /// (attaque distribuée) : ralentit sans bloquer le propriétaire.
    pub fn tarpit(&self) -> Duration {
        let now = Instant::now();
        let n = self.global.lock().iter().filter(|t| now.duration_since(**t) < Duration::from_secs(300)).count();
        Duration::from_millis((250 + n as u64 * 40).min(4000))
    }

    // --- sessions ---

    pub fn create_session(&self, ip: &str) -> String {
        let token = random_hex(32);
        let now = now_ms();
        let mut g = self.sessions.lock();
        g.retain(|_, s| now.saturating_sub(s.last_seen) < IDLE_MS && now.saturating_sub(s.created) < ABSOLUTE_MS);
        while g.len() >= MAX_SESSIONS {
            let Some(oldest) = g.iter().min_by_key(|(_, s)| s.last_seen).map(|(k, _)| k.clone()) else { break };
            g.remove(&oldest);
        }
        g.insert(token_hash(&token), Session { created: now, last_seen: now, ip: ip.into() });
        token
    }

    pub fn validate(&self, token: &str) -> bool {
        let key = token_hash(token);
        let now = now_ms();
        let mut g = self.sessions.lock();
        match g.get_mut(&key) {
            Some(s) if now.saturating_sub(s.last_seen) < IDLE_MS && now.saturating_sub(s.created) < ABSOLUTE_MS => {
                s.last_seen = now;
                true
            }
            Some(_) => {
                g.remove(&key);
                false
            }
            None => false,
        }
    }

    pub fn revoke(&self, token: &str) {
        self.sessions.lock().remove(&token_hash(token));
    }

    /// Supprime toutes les sessions sauf celle indiquée.
    pub fn revoke_others(&self, keep: Option<&str>) {
        let keep = keep.map(token_hash);
        self.sessions.lock().retain(|k, _| Some(k) == keep.as_ref());
    }

    pub fn sessions(&self, current: Option<&str>) -> Vec<SessionInfo> {
        let cur = current.map(token_hash);
        let mut v: Vec<_> = self
            .sessions
            .lock()
            .iter()
            .map(|(k, s)| SessionInfo { ip: s.ip.clone(), created: s.created, last_seen: s.last_seen, current: Some(k) == cur.as_ref() })
            .collect();
        v.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let mut n = NodeFile::default();
        n.pw = Some(hash_pw("correct horse"));
        assert!(verify_pw(&n, "correct horse"));
        assert!(!verify_pw(&n, "wrong"));
    }

    #[test]
    fn lockout_escalates() {
        let a = Auth::default();
        for _ in 0..FREE_FAILURES {
            assert!(a.failure("1.2.3.4").is_none());
        }
        assert_eq!(a.failure("1.2.3.4"), Some(Duration::from_secs(60)));
        assert!(a.locked("1.2.3.4").is_some());
        assert_eq!(a.failure("1.2.3.4"), Some(Duration::from_secs(120)));
        assert!(a.locked("5.6.7.8").is_none());
        a.success("1.2.3.4");
        assert!(a.locked("1.2.3.4").is_none());
    }

    #[test]
    fn unlock_resets_counters() {
        let a = Auth::default();
        for _ in 0..=FREE_FAILURES {
            a.failure("1.2.3.4");
        }
        a.failure("5.6.7.8");
        assert!(a.locked("1.2.3.4").is_some());
        assert_eq!(a.unlock("1.2.3.4"), 1);
        assert!(a.locked("1.2.3.4").is_none());
        assert_eq!(a.unlock(""), 1);
    }

    #[test]
    fn sessions_lifecycle() {
        let a = Auth::default();
        let t = a.create_session("1.1.1.1");
        assert!(a.validate(&t));
        assert!(!a.validate("nope"));
        a.revoke(&t);
        assert!(!a.validate(&t));
    }
}
