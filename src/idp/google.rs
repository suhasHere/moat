use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{IdpVerifier, UserIdentity};

const GOOGLE_CERTS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

#[derive(Deserialize)]
struct GoogleCerts {
    keys: Vec<GoogleKey>,
}

#[derive(Deserialize, Clone)]
struct GoogleKey {
    kid: String,
    n: String,
    e: String,
}

#[derive(Deserialize)]
struct GoogleClaims {
    sub: String,
    email: String,
    name: Option<String>,
    aud: String,
    iss: String,
    exp: u64,
}

pub struct GoogleIdp {
    client_id: String,
    http: Client,
    keys: Arc<RwLock<Vec<GoogleKey>>>,
}

impl GoogleIdp {
    pub async fn new(client_id: String) -> anyhow::Result<Self> {
        let http = Client::new();
        let keys = fetch_google_keys(&http).await?;

        Ok(Self {
            client_id,
            http,
            keys: Arc::new(RwLock::new(keys)),
        })
    }

    async fn get_key(&self, kid: &str) -> anyhow::Result<GoogleKey> {
        {
            let keys = self.keys.read().await;
            if let Some(key) = keys.iter().find(|k| k.kid == kid) {
                return Ok(key.clone());
            }
        }

        // Key not found — refresh
        let new_keys = fetch_google_keys(&self.http).await?;
        let mut keys = self.keys.write().await;
        *keys = new_keys;

        keys.iter()
            .find(|k| k.kid == kid)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("google key {kid} not found after refresh"))
    }
}

#[async_trait]
impl IdpVerifier for GoogleIdp {
    async fn verify(&self, id_token: &str) -> anyhow::Result<UserIdentity> {
        let header = decode_header(id_token)?;
        let kid = header.kid.ok_or_else(|| anyhow::anyhow!("missing kid in token header"))?;

        let key_data = self.get_key(&kid).await?;
        let decoding_key = DecodingKey::from_rsa_components(&key_data.n, &key_data.e)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);

        let token_data = decode::<GoogleClaims>(id_token, &decoding_key, &validation)?;
        let claims = token_data.claims;

        Ok(UserIdentity {
            subject: claims.sub,
            email: claims.email,
            name: claims.name,
            provider: "google",
        })
    }

    fn provider_name(&self) -> &'static str {
        "google"
    }
}

async fn fetch_google_keys(http: &Client) -> anyhow::Result<Vec<GoogleKey>> {
    let certs: GoogleCerts = http.get(GOOGLE_CERTS_URL).send().await?.json().await?;
    Ok(certs.keys)
}
