mod google;

use async_trait::async_trait;

use crate::config::Config;

pub use google::GoogleIdp;

#[derive(Debug, Clone)]
pub struct UserIdentity {
    pub subject: String,
    pub email: String,
    pub name: Option<String>,
    pub provider: &'static str,
}

#[async_trait]
pub trait IdpVerifier: Send + Sync {
    async fn verify(&self, token: &str) -> anyhow::Result<UserIdentity>;
    fn provider_name(&self) -> &'static str;
}

pub struct IdpRegistry {
    verifiers: Vec<Box<dyn IdpVerifier>>,
}

impl IdpRegistry {
    pub async fn from_config(config: &Config) -> anyhow::Result<Self> {
        let mut verifiers: Vec<Box<dyn IdpVerifier>> = Vec::new();

        if let Some(ref client_id) = config.google_client_id {
            let google = GoogleIdp::new(client_id.clone()).await?;
            tracing::info!("Google IdP enabled");
            verifiers.push(Box::new(google));
        }

        if verifiers.is_empty() {
            tracing::warn!("no IdP configured — token endpoint will reject all requests");
        }

        Ok(Self { verifiers })
    }

    pub async fn verify(&self, id_token: &str) -> anyhow::Result<UserIdentity> {
        for verifier in &self.verifiers {
            match verifier.verify(id_token).await {
                Ok(identity) => return Ok(identity),
                Err(_) => continue,
            }
        }
        anyhow::bail!("no IdP could validate the token")
    }
}
