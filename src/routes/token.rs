use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db;
use crate::error::AppError;
use crate::token::{MintRequest, TokenRole};
use crate::AppState;

#[derive(Deserialize)]
pub struct MintTokenRequest {
    pub room_id: Uuid,
    pub role: Option<TokenRole>,
}

#[derive(Serialize)]
pub struct MintTokenResponse {
    pub token: String,
    pub token_type: u64,
    pub expires_in: u64,
}

pub async fn mint_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<MintTokenRequest>,
) -> Result<Json<MintTokenResponse>, AppError> {
    let id_token = extract_bearer(&headers)?;

    let identity = state
        .idp
        .verify(&id_token)
        .await
        .map_err(|e| AppError::Unauthorized(format!("IdP verification failed: {e}")))?;

    let user = db::upsert_user(
        state.db.pool(),
        &identity.email,
        identity.provider,
        &identity.subject,
        identity.name.as_deref(),
    )
    .await?;

    let room = db::get_room_by_id(state.db.pool(), body.room_id)
        .await?
        .ok_or_else(|| AppError::NotFound("room not found".into()))?;

    let member_role = db::get_member_role(state.db.pool(), room.id, user.id)
        .await?
        .ok_or_else(|| AppError::Forbidden("not a member of this room".into()))?;

    let token_role = resolve_role(body.role, member_role)?;

    let namespace_parts: Vec<Vec<u8>> = room
        .namespace_prefix
        .split('/')
        .map(|s| s.as_bytes().to_vec())
        .collect();

    let minted = state.minter.mint(&MintRequest {
        subject: user.email.clone(),
        namespace_parts,
        role: token_role,
        lifetime_secs: state.config.token_lifetime_secs,
    })?;

    Ok(Json(MintTokenResponse {
        token: minted.token,
        token_type: minted.token_type,
        expires_in: minted.expires_in,
    }))
}

fn extract_bearer(headers: &HeaderMap) -> Result<String, AppError> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".into()))?;

    if !auth.starts_with("Bearer ") {
        return Err(AppError::Unauthorized("expected Bearer token".into()));
    }

    Ok(auth[7..].to_string())
}

fn resolve_role(
    requested: Option<TokenRole>,
    membership: db::MemberRole,
) -> Result<TokenRole, AppError> {
    let effective = match membership {
        db::MemberRole::Admin => requested.unwrap_or(TokenRole::PubSub),
        db::MemberRole::Publisher => {
            let role = requested.unwrap_or(TokenRole::Publisher);
            if role == TokenRole::Subscriber {
                return Err(AppError::Forbidden(
                    "publisher members cannot request subscriber-only tokens".into(),
                ));
            }
            role
        }
        db::MemberRole::Subscriber => {
            let role = requested.unwrap_or(TokenRole::Subscriber);
            if role != TokenRole::Subscriber {
                return Err(AppError::Forbidden(
                    "subscriber members can only get subscriber tokens".into(),
                ));
            }
            role
        }
    };
    Ok(effective)
}
