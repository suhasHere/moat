use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::db;
use crate::error::AppError;
use crate::AppState;

#[derive(Deserialize, ToSchema)]
pub struct GuestLoginRequest {
    pub display_name: String,
}

#[derive(Serialize, ToSchema)]
pub struct AuthResponse {
    pub user_id: uuid::Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub provider: String,
    pub session_token: String,
}

#[utoipa::path(
    post,
    path = "/v1/auth/guest",
    request_body = GuestLoginRequest,
    responses(
        (status = 200, description = "Guest session created", body = AuthResponse),
        (status = 400, description = "Invalid display name"),
    ),
    tag = "auth"
)]
pub async fn guest_login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<GuestLoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let name = body.display_name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return Err(AppError::BadRequest("display_name must be 1-64 characters".into()));
    }

    let guest_id = uuid::Uuid::new_v4();
    let email = format!("guest-{}@moat.local", &guest_id.to_string()[..8]);
    let subject = guest_id.to_string();

    let user = db::upsert_user(
        state.db.pool(),
        &email,
        "guest",
        &subject,
        Some(&name),
    )
    .await?;

    let session_token = create_session_token(user.id, &state.config.session_secret);

    Ok(Json(AuthResponse {
        user_id: user.id,
        email: user.email,
        display_name: user.display_name,
        provider: "guest".to_string(),
        session_token,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/auth/google",
    responses(
        (status = 200, description = "Google OAuth session created", body = AuthResponse),
        (status = 401, description = "Invalid or missing Bearer token"),
    ),
    security(("bearer" = [])),
    tag = "auth"
)]
pub async fn google_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<AuthResponse>, AppError> {
    let id_token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::Unauthorized("missing Bearer token".into()))?;

    let identity = state
        .idp
        .verify(id_token)
        .await
        .map_err(|e| AppError::Unauthorized(format!("Google verification failed: {e}")))?;

    let user = db::upsert_user(
        state.db.pool(),
        &identity.email,
        identity.provider,
        &identity.subject,
        identity.name.as_deref(),
    )
    .await?;

    let session_token = create_session_token(user.id, &state.config.session_secret);

    Ok(Json(AuthResponse {
        user_id: user.id,
        email: user.email,
        display_name: user.display_name,
        provider: identity.provider.to_string(),
        session_token,
    }))
}

fn create_session_token(user_id: uuid::Uuid, secret: &str) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let payload = format!("{}:{}", user_id, chrono::Utc::now().timestamp());
    let sig_input = format!("{}{}", payload, secret);
    let hash = simple_hash(sig_input.as_bytes());
    let token = format!("{}.{}", payload, hash);
    URL_SAFE_NO_PAD.encode(token.as_bytes())
}

pub fn verify_session_token(token: &str, secret: &str) -> Option<uuid::Uuid> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    let token_str = String::from_utf8(decoded).ok()?;
    let parts: Vec<&str> = token_str.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let (hash, payload) = (parts[0], parts[1]);

    let sig_input = format!("{}{}", payload, secret);
    let expected_hash = simple_hash(sig_input.as_bytes());
    if hash != expected_hash {
        return None;
    }

    let user_id_str = payload.split(':').next()?;
    uuid::Uuid::parse_str(user_id_str).ok()
}

fn simple_hash(data: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", h)
}
