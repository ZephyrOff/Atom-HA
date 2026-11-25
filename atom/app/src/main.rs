mod api;
mod auth;
mod clients;
mod dnsserver;
mod dnswire;
mod engine;
mod filter;
mod lists;
mod model;
mod qlog;
mod resolver;
mod state;
mod store;
mod sync;
mod upstream;

use arc_swap::ArcSwap;
use engine::Engine;
use parking_lot::Mutex;
use state::{App, ListMeta, RunCfg};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::Store;
use tokio::sync::Notify;

fn parse_args() -> RunCfg {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let mut cfg = RunCfg {
        data_dir: PathBuf::from(env("ATOM_DATA_DIR").unwrap_or_else(|| "./data".into())),
        dns_listen: env("ATOM_DNS_LISTEN").unwrap_or_else(|| "0.0.0.0:53".into()),
        http_listen: env("ATOM_HTTP_LISTEN").unwrap_or_else(|| "0.0.0.0:3000".into()),
        node_name: env("ATOM_NODE_NAME"),
        password: env("ATOM_PASSWORD"),
        trusted_ip: env("ATOM_TRUSTED_IP"),
        advertise_url: env("ATOM_ADVERTISE_URL"),
        log_retention: env("ATOM_LOG_RETENTION").and_then(|v| v.parse().ok()).unwrap_or(100_000),
        trusted_proxies: env("ATOM_TRUSTED_PROXIES").map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().unwrap_or_default();
        match a.as_str() {
            "--data-dir" => cfg.data_dir = PathBuf::from(val()),
            "--dns-listen" => cfg.dns_listen = val(),
            "--http-listen" => cfg.http_listen = val(),
            "--node-name" => cfg.node_name = Some(val()),
            "--password" => cfg.password = Some(val()),
            "--trusted-ip" => cfg.trusted_ip = Some(val()),
            "--advertise-url" => cfg.advertise_url = Some(val()),
            "--trusted-proxies" => cfg.trusted_proxies = val().split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            "-h" | "--help" => {
                println!(
                    "Atom {}\n\nOptions (ou variables ATOM_*) :\n  --data-dir <dir>        dossier de données (ATOM_DATA_DIR, défaut ./data)\n  --dns-listen <addr>     écoute DNS (ATOM_DNS_LISTEN, défaut 0.0.0.0:53)\n  --http-listen <addr>    écoute web/API (ATOM_HTTP_LISTEN, défaut 0.0.0.0:3000)\n  --node-name <nom>       nom du nœud (ATOM_NODE_NAME)\n  --password <mdp>        mot de passe admin (ATOM_PASSWORD)\n  --trusted-ip <ip>       IP admise sans mot de passe, ex. ingress Home Assistant (ATOM_TRUSTED_IP)\n  --advertise-url <url>   URL de ce nœud visible par les autres (ATOM_ADVERTISE_URL)
  --trusted-proxies <ips> IP de reverse proxies autorisés à fournir X-Forwarded-For (ATOM_TRUSTED_PROXIES)",
                    state::VERSION
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("option inconnue : {other} (voir --help)");
                std::process::exit(2);
            }
        }
    }
    cfg
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "atom=info".into()))
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = parse_args();
    std::fs::create_dir_all(cfg.data_dir.join("lists"))?;
    let (node, generated) = state::load_node(&cfg)?;
    if let Some(pw) = generated {
        tracing::warn!("Mot de passe administrateur généré (utilisateur « admin ») : {pw}");
    }
    tracing::info!("Atom {} · nœud « {} » ({})", state::VERSION, node.name, node.node_id);

    let store = Arc::new(Store::open(cfg.data_dir.join("config.json"), &node.node_id)?);
    model::seed_defaults(&store);
    let qlog = Arc::new(qlog::QLog::open(cfg.data_dir.join("querylog.json"), &node.node_id, cfg.log_retention));
    let lists_meta: HashMap<String, ListMeta> = std::fs::read(cfg.data_dir.join("lists").join("meta.json"))
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_default();

    let app = Arc::new(App {
        cfg: cfg.clone(),
        node: Mutex::new(node),
        store,
        qlog,
        engine: ArcSwap::from_pointee(Engine::empty()),
        cache: Mutex::new(HashMap::new()),
        health: Default::default(),
        lists_meta: Mutex::new(lists_meta),
        parse_cache: Mutex::new(HashMap::new()),
        rebuild: Notify::new(),
        sync_wake: Notify::new(),
        peer_status: Mutex::new(HashMap::new()),
        started: Instant::now(),
        http: reqwest::Client::builder().user_agent(format!("atom/{}", state::VERSION)).build()?,
        dns_ok: std::sync::atomic::AtomicBool::new(false),
        auth: auth::Auth::default(),
        cache_hits: Default::default(),
        cache_misses: Default::default(),
        pw_locked: cfg.password.as_ref().map_or(false, |p| !p.is_empty()),
    });

    // Premier moteur, construit avant d'accepter des requêtes.
    {
        let a = app.clone();
        let eng = tokio::task::spawn_blocking(move || Engine::build(&a)).await?;
        app.engine.store(Arc::new(eng));
    }

    // Reconstruction du moteur à chaque changement de configuration.
    {
        let app = app.clone();
        tokio::spawn(async move {
            let mut rx = app.store.version.subscribe();
            loop {
                tokio::select! {
                    _ = rx.changed() => {}
                    _ = app.rebuild.notified() => {}
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
                rx.borrow_and_update();
                let a = app.clone();
                if let Ok(eng) = tokio::task::spawn_blocking(move || Engine::build(&a)).await {
                    app.engine.store(Arc::new(eng));
                    app.cache.lock().clear();
                }
            }
        });
    }

    // Sauvegardes périodiques.
    {
        let app = app.clone();
        tokio::spawn(async move {
            let mut rx = app.store.version.subscribe();
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    r = rx.changed() => {
                        if r.is_err() { break; }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        rx.borrow_and_update();
                        app.store.save();
                    }
                    _ = tick.tick() => {
                        let a = app.clone();
                        let _ = tokio::task::spawn_blocking(move || a.qlog.save_if_dirty()).await;
                    }
                }
            }
        });
    }

    // Surveillance de l'état des upstreams.
    {
        let app = app.clone();
        tokio::spawn(async move {
            loop {
                let ups = app.engine.load().upstreams.clone();
                let mut set = tokio::task::JoinSet::new();
                for u in ups {
                    let h = app.health.clone();
                    set.spawn(async move {
                        let _ = upstream::probe(&u, &h).await;
                    });
                }
                while set.join_next().await.is_some() {}
                tokio::time::sleep(Duration::from_secs(20)).await;
            }
        });
    }

    tokio::spawn(lists::run(app.clone()));
    tokio::spawn(sync::run(app.clone()));

    // Serveur DNS : une erreur d'écoute (port 53 occupé) n'empêche pas l'interface de démarrer.
    {
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = dnsserver::run(app).await {
                tracing::error!("serveur DNS arrêté : {e}");
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(&cfg.http_listen)
        .await
        .map_err(|e| anyhow::anyhow!("écoute HTTP sur {} impossible : {e}", cfg.http_listen))?;
    tracing::info!("interface web sur http://{}", cfg.http_listen);
    let router = api::router(app.clone()).into_make_service_with_connect_info::<std::net::SocketAddr>();
    let a = app.clone();
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            tracing::info!("arrêt en cours, sauvegarde...");
            a.store.save();
            a.qlog.save_if_dirty();
        })
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("signal");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
