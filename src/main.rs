mod config;
mod db;
mod error;
mod idp;
mod openapi;
mod routes;
mod token;

use std::sync::Arc;

use axum::Router;
use clap::Parser;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use utoipa_swagger_ui::SwaggerUi;

use crate::config::Config;
use crate::db::Database;
use crate::idp::IdpRegistry;
use crate::openapi::ApiDoc;
use crate::token::MinterRegistry;

pub struct AppState {
    pub db: Database,
    pub idp: IdpRegistry,
    pub minter: MinterRegistry,
    pub config: Config,
    pub pp_signing_key: Option<ed25519_dalek::SigningKey>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::parse();

    let db = Database::connect(&config.database_url).await?;
    db.migrate().await?;

    let idp = IdpRegistry::from_config(&config).await?;
    let minter = MinterRegistry::from_config(&config)?;

    let pp_signing_key = if let Some(path) = &config.pp_signing_key {
        let pem = std::fs::read_to_string(path)?;
        let sk = load_ed25519_signing_key(&pem)?;
        tracing::info!("PP attester signing key loaded");
        Some(sk)
    } else {
        None
    };

    let state = Arc::new(AppState {
        db,
        idp,
        minter,
        config: config.clone(),
        pp_signing_key,
    });

    let app = Router::new()
        .merge(routes::router())
        .with_state(state)
        .merge(
            SwaggerUi::new("/docs/{_:.*}")
                .url("/api-doc/openapi.json", ApiDoc::spec()),
        )
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    tracing::info!("moat listening on {}", config.bind);

    axum::serve(listener, app).await?;
    Ok(())
}

fn load_ed25519_signing_key(pem: &str) -> anyhow::Result<ed25519_dalek::SigningKey> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
        .map_err(|e| anyhow::anyhow!("failed to load Ed25519 signing key: {e}"))
}
