use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use blind_rsa_signatures::pbrsa::{
    DefaultRng, PartiallyBlindKeyPair, PartiallyBlindPublicKey, PartiallyBlindSecretKey,
};
use blind_rsa_signatures::{Deterministic, KeyPair, PublicKey, SecretKey, Sha384, PSSZero};
use clap::Parser;
use ed25519_dalek::{Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use tower_http::cors::CorsLayer;

const TOKEN_TYPE_BLIND_RSA: u16 = 0x0002;
const TOKEN_TYPE_PARTIALLY_BLIND_RSA: u16 = 0xda7a;
const NK: usize = 256; // 2048-bit RSA key produces 256-byte signatures/blinded messages

type BrSk = SecretKey<Sha384, PSSZero, Deterministic>;
type BrPk = PublicKey<Sha384, PSSZero, Deterministic>;
type BrKp = KeyPair<Sha384, PSSZero, Deterministic>;
type PbSk = PartiallyBlindSecretKey<Sha384, PSSZero, Deterministic>;
#[allow(dead_code)]
type PbPk = PartiallyBlindPublicKey<Sha384, PSSZero, Deterministic>;
type PbKp = PartiallyBlindKeyPair<Sha384, PSSZero, Deterministic>;

#[derive(Parser)]
struct Cli {
    #[arg(long, env = "PP_BIND", default_value = "127.0.0.1:3300")]
    bind: SocketAddr,

    #[arg(long, env = "PP_KEY_DIR", default_value = "/opt/pp-issuer/keys")]
    key_dir: PathBuf,

    /// Path to the Attester's Ed25519 public key (PEM). If set, /token-request
    /// requires a valid RFC 9421 HTTP Message Signature from this key.
    #[arg(long, env = "PP_ATTESTER_KEY")]
    attester_key: Option<PathBuf>,
}

struct IssuerState {
    blind_rsa_sk: BrSk,
    blind_rsa_pk_spki: Vec<u8>,
    blind_rsa_key_id: [u8; 32],

    pbrs_kp: PbKp,
    pbrs_pk_spki: Vec<u8>,
    pbrs_key_id: [u8; 32],

    attester_verifying_key: Option<VerifyingKey>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    std::fs::create_dir_all(&cli.key_dir)?;

    let attester_verifying_key = if let Some(path) = &cli.attester_key {
        let pem = std::fs::read_to_string(path)?;
        let vk = load_ed25519_public_key(&pem)?;
        tracing::info!("attester signature verification enabled");
        Some(vk)
    } else {
        tracing::warn!("no --attester-key set: /token-request is unauthenticated");
        None
    };

    let mut issuer_state = load_or_generate_keys(&cli.key_dir)?;
    issuer_state.attester_verifying_key = attester_verifying_key;
    let state = Arc::new(issuer_state);

    let app = Router::new()
        .route(
            "/.well-known/private-token-issuer-directory",
            get(issuer_directory),
        )
        .route("/token-request", post(token_request))
        .layer(CorsLayer::permissive())
        .with_state(state);

    tracing::info!("pp-issuer listening on {}", cli.bind);
    let listener = tokio::net::TcpListener::bind(cli.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_ed25519_public_key(pem: &str) -> anyhow::Result<VerifyingKey> {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    VerifyingKey::from_public_key_pem(pem)
        .map_err(|e| anyhow::anyhow!("failed to load attester Ed25519 key: {e}"))
}

fn load_or_generate_keys(key_dir: &PathBuf) -> anyhow::Result<IssuerState> {
    let brsa_path = key_dir.join("blind-rsa.pem");
    let pbrs_path = key_dir.join("pbrs.pem");

    // Blind RSA (0x0002)
    let (blind_rsa_sk, blind_rsa_pk): (BrSk, BrPk) = if brsa_path.exists() {
        tracing::info!("loading Blind RSA key from {}", brsa_path.display());
        let pem = std::fs::read_to_string(&brsa_path)?;
        let sk = BrSk::from_pem(&pem)?;
        let pk = sk.public_key()?;
        (sk, pk)
    } else {
        tracing::info!("generating Blind RSA 2048-bit key");
        let kp = BrKp::generate(&mut DefaultRng, 2048)?;
        std::fs::write(&brsa_path, kp.sk.to_pem()?)?;
        tracing::info!("saved to {}", brsa_path.display());
        (kp.sk, kp.pk)
    };

    let blind_rsa_pk_spki = blind_rsa_pk.to_spki()?;
    let blind_rsa_key_id = sha256(&blind_rsa_pk_spki);

    // Partially Blind RSA (0xda7a) — safe primes required
    let pbrs_kp: PbKp = if pbrs_path.exists() {
        tracing::info!("loading PBRS key from {}", pbrs_path.display());
        let pem = std::fs::read_to_string(&pbrs_path)?;
        let sk = PbSk::from_pem(&pem)?;
        let pk = sk.public_key()?;
        PbKp { pk, sk }
    } else {
        tracing::info!("generating PBRS 2048-bit key (safe primes — may take a minute)");
        let kp = PbKp::generate(&mut DefaultRng, 2048)?;
        std::fs::write(&pbrs_path, kp.sk.to_pem()?)?;
        tracing::info!("saved to {}", pbrs_path.display());
        kp
    };

    let pbrs_pk_spki = pbrs_kp.pk.to_der()?;
    let pbrs_key_id = sha256(&pbrs_pk_spki);

    tracing::info!("Blind RSA truncated key ID: 0x{:02x}", blind_rsa_key_id[31]);
    tracing::info!("PBRS truncated key ID: 0x{:02x}", pbrs_key_id[31]);

    Ok(IssuerState {
        blind_rsa_sk,
        blind_rsa_pk_spki,
        blind_rsa_key_id,
        pbrs_kp,
        pbrs_pk_spki,
        pbrs_key_id,
        attester_verifying_key: None,
    })
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[derive(serde::Serialize)]
struct IssuerDirectory {
    #[serde(rename = "issuer-request-uri")]
    issuer_request_uri: String,
    #[serde(rename = "token-keys")]
    token_keys: Vec<TokenKeyEntry>,
}

#[derive(serde::Serialize)]
struct TokenKeyEntry {
    #[serde(rename = "token-type")]
    token_type: u16,
    #[serde(rename = "token-key")]
    token_key: String,
}

async fn issuer_directory(State(state): State<Arc<IssuerState>>) -> Json<IssuerDirectory> {
    Json(IssuerDirectory {
        issuer_request_uri: "/token-request".to_string(),
        token_keys: vec![
            TokenKeyEntry {
                token_type: TOKEN_TYPE_BLIND_RSA,
                token_key: URL_SAFE_NO_PAD.encode(&state.blind_rsa_pk_spki),
            },
            TokenKeyEntry {
                token_type: TOKEN_TYPE_PARTIALLY_BLIND_RSA,
                token_key: URL_SAFE_NO_PAD.encode(&state.pbrs_pk_spki),
            },
        ],
    })
}

async fn token_request(
    State(state): State<Arc<IssuerState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Verify attester signature if configured (RFC 9421)
    if let Some(vk) = &state.attester_verifying_key {
        if let Err(e) = verify_http_signature(&headers, &body, vk) {
            tracing::warn!("attester signature rejected: {e}");
            return (StatusCode::UNAUTHORIZED, format!("signature verification failed: {e}")).into_response();
        }
    }

    if body.len() < 3 {
        return (StatusCode::BAD_REQUEST, "request too short").into_response();
    }

    let token_type = u16::from_be_bytes([body[0], body[1]]);

    match token_type {
        TOKEN_TYPE_BLIND_RSA => match sign_blind_rsa(&state, &body) {
            Ok(r) => r,
            Err(e) => e.into_response(),
        },
        TOKEN_TYPE_PARTIALLY_BLIND_RSA => match sign_pbrs(&state, &body) {
            Ok(r) => r,
            Err(e) => e.into_response(),
        },
        _ => (
            StatusCode::BAD_REQUEST,
            format!("unsupported token type: 0x{:04x}", token_type),
        )
            .into_response(),
    }
}

/// Verify RFC 9421 HTTP Message Signature.
/// Simplified: covers Content-Digest header (SHA-256 of body).
/// Signature-Input: sig1=("content-digest");alg="ed25519";keyid="attester"
/// Signature: sig1=:<base64 of Ed25519 signature over signature base>:
fn verify_http_signature(
    headers: &HeaderMap,
    body: &[u8],
    vk: &VerifyingKey,
) -> Result<(), String> {
    let sig_input = headers.get("signature-input")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing Signature-Input header")?;

    let signature_header = headers.get("signature")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing Signature header")?;

    let content_digest = headers.get("content-digest")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing Content-Digest header")?;

    // Verify Content-Digest matches body
    let body_hash = Sha256::digest(body);
    let expected_digest = format!("sha-256=:{}:", STANDARD.encode(body_hash));
    if content_digest != expected_digest {
        return Err("Content-Digest mismatch".to_string());
    }

    // Build signature base per RFC 9421 §2.5
    // "content-digest": <value>\n
    // "@signature-params": <sig_input_params>
    let params = sig_input.strip_prefix("sig1=").ok_or("bad Signature-Input format")?;
    let sig_base = format!(
        "\"content-digest\": {}\n\"@signature-params\": {}",
        content_digest, params
    );

    // Extract signature bytes
    let sig_b64 = signature_header
        .strip_prefix("sig1=:")
        .and_then(|s| s.strip_suffix(':'))
        .ok_or("bad Signature header format")?;
    let sig_bytes = STANDARD.decode(sig_b64).map_err(|e| format!("bad signature encoding: {e}"))?;

    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("invalid signature: {e}"))?;

    vk.verify(sig_base.as_bytes(), &signature)
        .map_err(|_| "signature verification failed".to_string())
}

fn sign_blind_rsa(
    state: &IssuerState,
    body: &[u8],
) -> Result<Response, (StatusCode, String)> {
    // TokenRequest: token_type(2) + truncated_token_key_id(1) + blinded_msg(Nk=256)
    if body.len() != 3 + NK {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("expected {} bytes, got {}", 3 + NK, body.len()),
        ));
    }

    let truncated_key_id = body[2];
    if truncated_key_id != state.blind_rsa_key_id[31] {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "key ID mismatch: 0x{:02x} != 0x{:02x}",
                truncated_key_id, state.blind_rsa_key_id[31]
            ),
        ));
    }

    let blinded_msg = &body[3..3 + NK];
    let blind_sig = state.blind_rsa_sk.blind_sign(blinded_msg).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("blind sign failed: {e}"),
        )
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/private-token-response")
        .body(axum::body::Body::from(blind_sig.0))
        .unwrap())
}

fn sign_pbrs(
    state: &IssuerState,
    body: &[u8],
) -> Result<Response, (StatusCode, String)> {
    // ExtendedTokenRequest:
    //   token_type(2) + truncated_token_key_id(1) + blinded_msg(Nk=256)
    //   + extensions_length(2) + extensions_data(variable)
    if body.len() < 3 + NK + 2 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "PBRS request too short".to_string(),
        ));
    }

    let truncated_key_id = body[2];
    if truncated_key_id != state.pbrs_key_id[31] {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "PBRS key ID mismatch: 0x{:02x} != 0x{:02x}",
                truncated_key_id, state.pbrs_key_id[31]
            ),
        ));
    }

    let blinded_msg = &body[3..3 + NK];

    // Extensions follow the token request
    let ext_offset = 3 + NK;
    let ext_len = u16::from_be_bytes([body[ext_offset], body[ext_offset + 1]]) as usize;
    let ext_total = ext_offset + 2 + ext_len;
    if body.len() < ext_total {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "extensions truncated".to_string(),
        ));
    }

    // The full serialized extensions (including the 2-byte length prefix)
    let extensions_bytes = &body[ext_offset..ext_total];

    tracing::info!(
        "PBRS sign: body={}B, blinded_msg={}B, extensions={}B, ext_hex={:02x?}",
        body.len(),
        blinded_msg.len(),
        extensions_bytes.len(),
        &extensions_bytes[..std::cmp::min(extensions_bytes.len(), 20)]
    );

    // Derive signing key for this metadata
    let derived_sk = state
        .pbrs_kp
        .derive_secret_key_for_metadata(extensions_bytes)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("derive key failed: {e}"),
            )
        })?;

    let blind_sig = derived_sk.blind_sign(blinded_msg).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("PBRS blind sign failed: {e}"),
        )
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/private-token-response")
        .body(axum::body::Body::from(blind_sig.0))
        .unwrap())
}
