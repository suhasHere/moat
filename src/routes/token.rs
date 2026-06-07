use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db;
use crate::error::AppError;
use crate::routes::auth::verify_session_token;
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
    let user_id = authenticate(&headers, &state)?;

    let room = db::get_room_by_id(state.db.pool(), body.room_id)
        .await?
        .ok_or_else(|| AppError::NotFound("room not found".into()))?;

    let member_role = db::get_member_role(state.db.pool(), room.id, user_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("not a member of this room".into()))?;

    let token_role = resolve_role(body.role, member_role)?;

    let namespace_parts: Vec<Vec<u8>> = room
        .namespace_prefix
        .split('/')
        .map(|s| s.as_bytes().to_vec())
        .collect();

    let user = db::get_user_by_id(state.db.pool(), user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("user not found".into()))?;

    let minted = state.minter.mint(&MintRequest {
        subject: user.email,
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

fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<Uuid, AppError> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".into()))?;

    let token = auth
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("expected Bearer token".into()))?;

    verify_session_token(token, &state.config.session_secret)
        .ok_or_else(|| AppError::Unauthorized("invalid session token".into()))
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
