mod c4m;

use crate::config::Config;

pub use c4m::C4mMinter;

#[derive(Debug, Clone)]
pub struct MintRequest {
    pub subject: String,
    pub namespace_parts: Vec<Vec<u8>>,
    pub role: TokenRole,
    pub lifetime_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TokenRole {
    Publisher,
    Subscriber,
    PubSub,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MintedToken {
    pub token: String,
    pub token_type: u64,
    pub expires_in: u64,
}

pub trait TokenMinter: Send + Sync {
    fn mint(&self, request: &MintRequest) -> anyhow::Result<MintedToken>;
    fn token_type_name(&self) -> &'static str;
}

pub struct MinterRegistry {
    minters: Vec<Box<dyn TokenMinter>>,
}

impl MinterRegistry {
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let mut minters: Vec<Box<dyn TokenMinter>> = Vec::new();

        if let Some(ref key_path) = config.c4m_private_key {
            let pem = std::fs::read_to_string(key_path)?;
            let c4m = C4mMinter::new(
                &pem,
                config.c4m_issuer.clone(),
                config.c4m_audience.clone(),
                config.token_lifetime_secs,
            )?;
            tracing::info!("C4M token minter enabled");
            minters.push(Box::new(c4m));
        }

        if minters.is_empty() {
            tracing::warn!("no token minter configured — token endpoint will fail");
        }

        Ok(Self { minters })
    }

    pub fn mint(&self, request: &MintRequest) -> anyhow::Result<MintedToken> {
        let minter = self
            .minters
            .first()
            .ok_or_else(|| anyhow::anyhow!("no token minter configured"))?;
        minter.mint(request)
    }
}
