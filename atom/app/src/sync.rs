//! Synchronisation entre nœuds.
//!
//! Chaque nœud interroge ses pairs (`/api/sync/pull`) en envoyant ses vecteurs de versions
//! et reçoit ce qui lui manque : objets de configuration et entrées du journal.
//! Lors d'un changement local, les pairs sont prévenus (`/api/sync/notify`) pour tirer
//! immédiatement. Une interrogation périodique rattrape tout retard.

use crate::qlog::LogEntry;
use crate::state::{App, Peer, PeerStatus};
use crate::store::{now_ms, Obj};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
pub struct PullReq {
    #[serde(default)]
    pub node_id: String,
    pub cfg_vv: HashMap<String, u64>,
    pub log_vv: HashMap<String, u64>,
}

#[derive(Serialize, Deserialize)]
pub struct PullResp {
    pub node_id: String,
    pub node_name: String,
    /// Adresse annoncée par le nœud qui répond.
    #[serde(default)]
    pub url: String,
    /// Les nœuds qu'il connaît : permet de former un maillage à partir de 3 nœuds.
    #[serde(default)]
    pub peers: Vec<Peer>,
    pub cfg: Vec<Obj>,
    pub logs: Vec<LogEntry>,
}

const LOG_BATCH: usize = 5000;

async fn pull_from(app: &Arc<App>, peer_id: &str, url: &str, token: &str) -> anyhow::Result<(usize, usize)> {
    let req = PullReq { node_id: app.node_id(), cfg_vv: app.store.vv(), log_vv: app.qlog.vv() };
    let t = Instant::now();
    let resp = app
        .sync_client
        .load_full()
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
    // Découverte des autres nœuds du cluster.
    {
        let me = app.node_id();
        let mut n = app.node.lock();
        let mut added = false;
        for p in r.peers.iter() {
            let url_ok = p.url.starts_with("http://") || p.url.starts_with("https://");
            if p.id != me && url_ok && !n.forgotten.contains(&p.id) && !n.peers.iter().any(|x| x.id == p.id) {
                tracing::info!("nœud « {} » découvert via {}", p.name, r.node_name);
                n.peers.push(Peer { id: p.id.clone(), name: p.name.clone(), url: p.url.trim_end_matches('/').to_string(), ca_pem: p.ca_pem.clone() });
                added = true;
            }
            // Mode « auto-signé » : on retient l'autorité des nœuds présentés par un nœud de confiance.
            if p.id != me && n.tls.cluster_mode == "selfsigned" && !p.ca_pem.is_empty() {
                let f = format!("peers/{}.crt", p.id);
                if crate::tls::read(app, &f).is_none() && crate::tls::certs_from_pem(&p.ca_pem).is_ok() {
                    let _ = crate::tls::write(app, &f, &p.ca_pem);
                    added = true;
                }
            }
        }
        drop(n);
        if added {
            app.save_node();
            crate::tls::refresh_sync_client(app);
            app.tls_reload.notify_one();
        }
    }
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
    if !req.node_id.is_empty() {
        app.store.note_peer_vv(&req.node_id, req.cfg_vv.clone());
    }
    let (url, peers) = {
        let n = app.node.lock();
        (n.advertise_url.clone(), n.peers.clone())
    };
    PullResp {
        node_id: app.node_id(),
        node_name: app.node_name(),
        url,
        peers,
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
            .sync_client
            .load_full()
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
