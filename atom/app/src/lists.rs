//! Téléchargement et synchronisation des listes de filtrage distantes.

use crate::filter::ParsedList;
use crate::model::ListCfg;
use crate::state::{App, ListMeta};
use crate::store::now_ms;
use anyhow::{anyhow, bail, Result};
use std::sync::Arc;

pub async fn refresh(app: &Arc<App>, id: &str, force: bool) -> Result<()> {
    let cfg: ListCfg = app
        .store
        .get("lists", id)
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or_else(|| anyhow!("liste introuvable"))?;
    if cfg.kind != "url" {
        return Ok(());
    }
    let prev = app.lists_meta.lock().get(id).cloned().unwrap_or_default();
    let mut req = app.http.get(&cfg.url).timeout(std::time::Duration::from_secs(120));
    if !force {
        if let Some(etag) = &prev.etag {
            req = req.header("if-none-match", etag);
        }
    }
    {
        let mut m = app.lists_meta.lock();
        m.entry(id.to_string()).or_default().last_attempt = now_ms();
    }
    let result: Result<()> = async {
        let resp = req.send().await?;
        let status = resp.status();
        if status.as_u16() == 304 {
            let mut m = app.lists_meta.lock();
            let e = m.entry(id.to_string()).or_default();
            e.updated_at = now_ms();
            e.error = None;
            return Ok(());
        }
        if !status.is_success() {
            bail!("HTTP {status}");
        }
        let etag = resp.headers().get("etag").and_then(|v| v.to_str().ok()).map(String::from);
        let text = resp.text().await?;
        let parsed = {
            let (id, name, text2) = (id.to_string(), cfg.name.clone(), text.clone());
            tokio::task::spawn_blocking(move || ParsedList::parse(&id, &name, &text2)).await?
        };
        if parsed.count == 0 {
            bail!("la liste ne contient aucune règle exploitable");
        }
        let dir = app.cfg.data_dir.join("lists");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(format!("{id}.txt")), &text)?;
        let updated = now_ms();
        {
            let mut m = app.lists_meta.lock();
            let e = m.entry(id.to_string()).or_default();
            e.updated_at = updated;
            e.etag = etag;
            e.rules = parsed.count;
            e.unsupported = parsed.unsupported;
            e.error = None;
        }
        app.parse_cache.lock().insert(id.to_string(), (format!("u{updated}"), Arc::new(parsed)));
        Ok(())
    }
    .await;
    if let Err(e) = &result {
        let mut m = app.lists_meta.lock();
        m.entry(id.to_string()).or_default().error = Some(e.to_string());
    }
    app.save_lists_meta();
    app.rebuild.notify_one();
    result
}

/// Boucle de fond : rafraîchit les listes dont l'intervalle est écoulé.
pub async fn run(app: Arc<App>) {
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    loop {
        let lists = app.store.list("lists");
        for (id, v, _) in lists {
            let Ok(cfg) = serde_json::from_value::<ListCfg>(v) else { continue };
            if cfg.kind != "url" || !cfg.enabled {
                continue;
            }
            let meta = app.lists_meta.lock().get(&id).cloned().unwrap_or_default();
            let now = now_ms();
            let due = meta.updated_at == 0 || now.saturating_sub(meta.updated_at) >= cfg.interval_hours.max(1) * 3_600_000;
            let retry_ok = now.saturating_sub(meta.last_attempt) >= 10 * 60_000;
            if due && retry_ok {
                if let Err(e) = refresh(&app, &id, false).await {
                    tracing::warn!("synchro de la liste {} : {e}", cfg.name);
                } else {
                    tracing::info!("liste {} synchronisée", cfg.name);
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}
