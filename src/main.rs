mod config;
mod db;
mod error;
mod idp;
mod routes;
mod token;

use std::sync::Arc;

use axum::Router;
use clap::Parser;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::db::Database;
use crate::idp::IdpRegistry;
use crate::token::MinterRegistry;

pub struct AppState {
    pub db: Database,
    pub idp: IdpRegistry,
    pub minter: MinterRegistry,
    pub config: Config,
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

    let state = Arc::new(AppState {
        db,
        idp,
        minter,
        config: config.clone(),
    });

    let app = Router::new()
        .merge(routes::router())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    tracing::info!("moat listening on {}", config.bind);

    axum::serve(listener, app).await?;
    Ok(())
}
