use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Clone, Debug)]
#[command(name = "moat", about = "Moat — MoQ Auth Token service")]
pub struct Config {
    /// Address to bind the HTTP server.
    #[arg(long, env = "MOAT_BIND", default_value = "0.0.0.0:3200")]
    pub bind: String,

    /// PostgreSQL connection URL.
    #[arg(long, env = "MOAT_DATABASE_URL")]
    pub database_url: String,

    /// Google OAuth2 Client ID for IdP verification.
    #[arg(long, env = "MOAT_GOOGLE_CLIENT_ID")]
    pub google_client_id: Option<String>,

    /// Path to ES256 private key PEM for C4M token signing.
    #[arg(long, env = "MOAT_C4M_PRIVATE_KEY")]
    pub c4m_private_key: Option<PathBuf>,

    /// Issuer claim for minted C4M tokens.
    #[arg(long, env = "MOAT_C4M_ISSUER", default_value = "moat")]
    pub c4m_issuer: String,

    /// Audience claim for minted C4M tokens.
    #[arg(long, env = "MOAT_C4M_AUDIENCE", default_value = "moq-relay")]
    pub c4m_audience: String,

    /// Default token lifetime in seconds.
    #[arg(long, env = "MOAT_TOKEN_LIFETIME", default_value = "3600")]
    pub token_lifetime_secs: u64,

    /// Secret for signing session tokens. Generate with: openssl rand -hex 32
    #[arg(long, env = "MOAT_SESSION_SECRET", default_value = "change-me-in-production")]
    pub session_secret: String,

    /// Base URL for generating invite links (e.g. https://chat.mocha-net.dev)
    #[arg(long, env = "MOAT_BASE_URL", default_value = "https://chat.mocha-net.dev")]
    pub base_url: String,
}
