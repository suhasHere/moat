use std::sync::Arc;

use anyhow::anyhow;
use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::AppState;

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub room_id: Option<String>,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub token_challenge: String,
    pub issuer_key: String,
}

/// POST /v1/auth/privacypass/challenge
///
/// Returns a TokenChallenge (RFC 9578 §2.1) and the issuer's public key.
/// The client uses these to obtain a Privacy Pass token from the issuer,
/// which it then presents to the relay as its AUTH_TOKEN.
pub async fn challenge(
    State(state): State<Arc<AppState>>,
    Json(_body): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    // Build TokenChallenge per RFC 9578 §2.1:
    //   struct {
    //     uint16 token_type;             // 0x0002 for public tokens
    //     opaque issuer_name<1..2^16-1>;
    //     opaque redemption_context<0..32>;
    //     opaque origin_info<0..2^16-1>;
    //   } TokenChallenge;
    let token_type: u16 = 0x0002;
    let issuer_name = state.config.pp_issuer_name.as_bytes();
    let origin_info = state.config.pp_origin_name.as_bytes();

    let mut redemption_context = [0u8; 32];
    rand::rng().fill_bytes(&mut redemption_context);

    let mut challenge = Vec::new();
    // token_type (2 bytes)
    challenge.extend_from_slice(&token_type.to_be_bytes());
    // issuer_name length-prefixed (2 bytes length)
    challenge.extend_from_slice(&(issuer_name.len() as u16).to_be_bytes());
    challenge.extend_from_slice(issuer_name);
    // redemption_context (1 byte length + 32 bytes)
    challenge.push(32u8);
    challenge.extend_from_slice(&redemption_context);
    // origin_info length-prefixed (2 bytes length)
    challenge.extend_from_slice(&(origin_info.len() as u16).to_be_bytes());
    challenge.extend_from_slice(origin_info);

    // Fetch issuer public key from the issuer directory
    let issuer_key = fetch_issuer_key(&state.config.pp_issuer_url).await?;

    Ok(Json(ChallengeResponse {
        token_challenge: URL_SAFE_NO_PAD.encode(&challenge),
        issuer_key: URL_SAFE_NO_PAD.encode(&issuer_key),
    }))
}

async fn fetch_issuer_key(issuer_url: &str) -> Result<Vec<u8>, AppError> {
    let url = format!("{}/.well-known/private-token-issuer-directory", issuer_url);
    let res = reqwest::get(&url)
        .await
        .map_err(|e| AppError::Internal(anyhow!("Failed to fetch issuer directory: {e}")))?;

    if !res.status().is_success() {
        return Err(AppError::Internal(anyhow!(
            "Issuer directory returned {}",
            res.status()
        )));
    }

    let body: serde_json::Value = res
        .json()
        .await
        .map_err(|e| AppError::Internal(anyhow!("Failed to parse issuer directory: {e}")))?;

    // Find the token-key for type 0x0002 (Blind RSA)
    let keys = body["token-keys"]
        .as_array()
        .ok_or_else(|| AppError::Internal(anyhow!("No token-keys in issuer directory")))?;

    for key in keys {
        if key["token-type"].as_u64() == Some(0x0002) {
            let key_b64 = key["token-key"]
                .as_str()
                .ok_or_else(|| AppError::Internal(anyhow!("token-key not a string")))?;
            let key_bytes = URL_SAFE_NO_PAD
                .decode(key_b64)
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(key_b64))
                .map_err(|e| AppError::Internal(anyhow!("Failed to decode issuer key: {e}")))?;
            return Ok(key_bytes);
        }
    }

    Err(AppError::Internal(anyhow!(
        "No public token key (0x0002) found in issuer directory"
    )))
}

/// POST /v1/auth/privacypass/token-request
///
/// Proxies the token request to the issuer (avoids CORS issues in browsers).
/// Client sends raw token request bytes, we forward to issuer and return response.
pub async fn token_request_proxy(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, AppError> {
    let url = format!("{}/token-request", state.config.pp_issuer_url);

    let client = reqwest::Client::new();
    let res = client
        .post(&url)
        .header("Content-Type", "message/token-request")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| AppError::Internal(anyhow!("Issuer request failed: {e}")))?;

    let status = res.status();
    let response_bytes = res
        .bytes()
        .await
        .map_err(|e| AppError::Internal(anyhow!("Failed to read issuer response: {e}")))?;

    Ok(axum::response::Response::builder()
        .status(status.as_u16())
        .header("Content-Type", "message/token-response")
        .body(axum::body::Body::from(response_bytes.to_vec()))
        .unwrap())
}
