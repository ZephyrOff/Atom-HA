//! Écoute UDP et TCP du serveur DNS.

use crate::dnswire;
use crate::resolver;
use crate::state::App;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

pub async fn run(app: Arc<App>) -> anyhow::Result<()> {
    let addr = app.cfg.dns_listen.clone();
    let udp = UdpSocket::bind(&addr)
        .await
        .map_err(|e| anyhow::anyhow!("écoute UDP sur {addr} impossible : {e}"))?;
    let udp = Arc::new(udp);
    let tcp = TcpListener::bind(&addr).await.map_err(|e| anyhow::anyhow!("écoute TCP sur {addr} impossible : {e}"))?;
    app.dns_ok.store(true, std::sync::atomic::Ordering::Relaxed);
    tracing::info!("DNS à l'écoute sur {addr} (UDP et TCP)");

    let a2 = app.clone();
    tokio::spawn(async move {
        loop {
            match tcp.accept().await {
                Ok((mut s, peer)) => {
                    let app = a2.clone();
                    tokio::spawn(async move {
                        loop {
                            let mut lb = [0u8; 2];
                            let r = tokio::time::timeout(std::time::Duration::from_secs(10), s.read_exact(&mut lb)).await;
                            if !matches!(r, Ok(Ok(_))) {
                                break;
                            }
                            let len = u16::from_be_bytes(lb) as usize;
                            let mut buf = vec![0u8; len];
                            if s.read_exact(&mut buf).await.is_err() {
                                break;
                            }
                            let Some(resp) = resolver::handle(&app, &buf, peer.ip()).await else { break };
                            let mut o = (resp.len() as u16).to_be_bytes().to_vec();
                            o.extend_from_slice(&resp);
                            if s.write_all(&o).await.is_err() {
                                break;
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("accept TCP : {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });

    let sem = Arc::new(tokio::sync::Semaphore::new(2048));
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match udp.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                // Sous Windows, un ICMP « port inaccessible » remonte comme une erreur de lecture.
                tracing::debug!("recv UDP : {e}");
                continue;
            }
        };
        let req = buf[..n].to_vec();
        let Ok(permit) = sem.clone().try_acquire_owned() else { continue };
        let app = app.clone();
        let udp = udp.clone();
        tokio::spawn(async move {
            let _p = permit;
            if let Some(q) = dnswire::parse_query(&req) {
                if let Some(resp) = resolver::handle(&app, &req, peer.ip()).await {
                    let resp = dnswire::truncate_for_udp(&resp, &q);
                    let _ = udp.send_to(&resp, peer).await;
                }
            }
        });
    }
}
