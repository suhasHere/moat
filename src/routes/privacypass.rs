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

const TOKEN_TYPE_BLIND_RSA: u16 = 0x0002;
const TOKEN_TYPE_PARTIALLY_BLIND_RSA: u16 = 0xda7a;
const EXTENSION_TYPE_MOQ_ACTIONS: u16 = 0x0001;

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub room_id: Option<String>,
    pub token_type: Option<u16>,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub token_type: u16,
    pub token_challenge: String,
    pub issuer_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<String>,
}

/// POST /v1/auth/privacypass/challenge
///
/// Returns a TokenChallenge (RFC 9578 §2.1) and the issuer's public key.
/// For PBRS (0xda7a), also returns serialized extensions with MoQ action scope.
pub async fn challenge(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    let token_type = body.token_type.unwrap_or(TOKEN_TYPE_PARTIALLY_BLIND_RSA);

    let issuer_name = state.config.pp_issuer_name.as_bytes();
    let origin_info = state.config.pp_origin_name.as_bytes();

    let mut redemption_context = [0u8; 32];
    rand::rng().fill_bytes(&mut redemption_context);

    // Build TokenChallenge per RFC 9578 §2.1
    let mut challenge = Vec::new();
    challenge.extend_from_slice(&token_type.to_be_bytes());
    challenge.extend_from_slice(&(issuer_name.len() as u16).to_be_bytes());
    challenge.extend_from_slice(issuer_name);
    challenge.push(32u8);
    challenge.extend_from_slice(&redemption_context);
    challenge.extend_from_slice(&(origin_info.len() as u16).to_be_bytes());
    challenge.extend_from_slice(origin_info);

    // Fetch the appropriate issuer key
    let issuer_key = fetch_issuer_key(&state.config.pp_issuer_url, token_type).await?;

    // For PBRS, build extensions with MoQ action scope
    let extensions = if token_type == TOKEN_TYPE_PARTIALLY_BLIND_RSA {
        let room_id = body.room_id.as_deref().unwrap_or("*");
        let ext_bytes = build_moq_extensions(room_id);
        Some(URL_SAFE_NO_PAD.encode(&ext_bytes))
    } else {
        None
    };

    Ok(Json(ChallengeResponse {
        token_type,
        token_challenge: URL_SAFE_NO_PAD.encode(&challenge),
        issuer_key: URL_SAFE_NO_PAD.encode(&issuer_key),
        extensions,
    }))
}

/// Build Privacy Pass Extensions carrying MoQ action scope.
/// Format: extensions_length(2) + [extension_type(2) + extension_data_length(2) + data]*
fn build_moq_extensions(room_id: &str) -> Vec<u8> {
    // Extension data: JSON-encoded MoQ action scope
    let scope = serde_json::json!({
        "pub": [format!("mocha/*/{}/*", room_id)],
        "sub": [format!("mocha/*/{}/*", room_id)],
    });
    let ext_data = serde_json::to_vec(&scope).unwrap();

    // Single extension: type(2) + data_length(2) + data
    let mut ext = Vec::new();
    ext.extend_from_slice(&EXTENSION_TYPE_MOQ_ACTIONS.to_be_bytes());
    ext.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
    ext.extend_from_slice(&ext_data);

    // Wrap in extensions envelope: total_length(2) + extensions
    let mut envelope = Vec::new();
    envelope.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    envelope.extend_from_slice(&ext);
    envelope
}

async fn fetch_issuer_key(issuer_url: &str, token_type: u16) -> Result<Vec<u8>, AppError> {
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

    let keys = body["token-keys"]
        .as_array()
        .ok_or_else(|| AppError::Internal(anyhow!("No token-keys in issuer directory")))?;

    for key in keys {
        if key["token-type"].as_u64() == Some(token_type as u64) {
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
        "No token key for type 0x{:04x} found in issuer directory",
        token_type
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
        .header("Content-Type", "application/private-token-request")
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
        .header("Content-Type", "application/private-token-response")
        .body(axum::body::Body::from(response_bytes.to_vec()))
        .unwrap())
}
