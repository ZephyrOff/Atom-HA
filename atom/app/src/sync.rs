//! Synchronisation entre nœuds.
//!
//! Chaque nœud interroge ses pairs (`/api/sync/pull`) en envoyant ses vecteurs de versions
//! et reçoit ce qui lui manque : objets de configuration et entrées du journal.
//! Lors d'un changement local, les pairs sont prévenus (`/api/sync/notify`) pour tirer
//! immédiatement. Une interrogation périodique rattrape tout retard.

use crate::qlog::LogEntry;
use crate::state::{App, PeerStatus};
use crate::store::{now_ms, Obj};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
pub struct PullReq {
    pub cfg_vv: HashMap<String, u64>,
    pub log_vv: HashMap<String, u64>,
}

#[derive(Serialize, Deserialize)]
pub struct PullResp {
    pub node_id: String,
    pub node_name: String,
    pub cfg: Vec<Obj>,
    pub logs: Vec<LogEntry>,
}

const LOG_BATCH: usize = 5000;

async fn pull_from(app: &Arc<App>, peer_id: &str, url: &str, token: &str) -> anyhow::Result<(usize, usize)> {
    let req = PullReq { cfg_vv: app.store.vv(), log_vv: app.qlog.vv() };
    let t = Instant::now();
    let resp = app
        .http
        .post(format!("{}/api/sync/pull", url.trim_end_matches('/')))
        .bearer_auth(token)
        .timeout(Duration::from_secs(15))
        .json(&req)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("HTTP {}", resp.status());
    }
    let r: PullResp = resp.json().await?;
    let (nc, nl) = (r.cfg.len(), r.logs.len());
    if nc > 0 {
        app.store.apply_remote(r.cfg);
    }
    if nl > 0 {
        app.qlog.apply_remote(r.logs);
    }
    let mut ps = app.peer_status.lock();
    let e = ps.entry(peer_id.to_string()).or_default();
    *e = PeerStatus {
        ok: true,
        last_ok: now_ms(),
        last_error: None,
        latency_ms: t.elapsed().as_millis() as u64,
        name: r.node_name,
    };
    Ok((nc, nl))
}

pub fn answer_pull(app: &Arc<App>, req: PullReq) -> PullResp {
    PullResp {
        node_id: app.node_id(),
        node_name: app.node_name(),
        cfg: app.store.pull(&req.cfg_vv),
        logs: app.qlog.pull(&req.log_vv, LOG_BATCH),
    }
}

pub async fn sync_once(app: &Arc<App>) {
    let (peers, token) = {
        let n = app.node.lock();
        (n.peers.clone(), n.cluster_token.clone())
    };
    for p in peers {
        match pull_from(app, &p.id, &p.url, &token).await {
            Ok((nc, nl)) => {
                if nc > 0 {
                    tracing::info!("synchro depuis {} : {nc} objet(s) de configuration", p.name);
                }
                let _ = nl;
            }
            Err(e) => {
                let mut ps = app.peer_status.lock();
                let s = ps.entry(p.id.clone()).or_default();
                s.ok = false;
                s.last_error = Some(e.to_string());
                if s.name.is_empty() {
                    s.name = p.name.clone();
                }
            }
        }
    }
}

async fn notify_peers(app: &Arc<App>) {
    let (peers, token) = {
        let n = app.node.lock();
        (n.peers.clone(), n.cluster_token.clone())
    };
    for p in peers {
        let _ = app
            .http
            .post(format!("{}/api/sync/notify", p.url.trim_end_matches('/')))
            .bearer_auth(&token)
            .timeout(Duration::from_secs(3))
            .send()
            .await;
    }
}

pub async fn run(app: Arc<App>) {
    // Prévient les pairs à chaque changement local.
    let a2 = app.clone();
    tokio::spawn(async move {
        let mut rx = a2.store.local_version.subscribe();
        while rx.changed().await.is_ok() {
            tokio::time::sleep(Duration::from_millis(100)).await;
            notify_peers(&a2).await;
        }
    });
    loop {
        sync_once(&app).await;
        tokio::select! {
            _ = app.sync_wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(3)) => {}
        }
    }
}
