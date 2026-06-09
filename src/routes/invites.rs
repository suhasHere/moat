use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::db;
use crate::error::AppError;
use crate::routes::auth::verify_session_token;
use crate::AppState;
use chrono::Utc;
use rand::Rng;

#[derive(Deserialize)]
pub struct CreateInviteRequest {
    pub max_uses: Option<i32>,
    pub expires_in_hours: Option<u64>,
}

#[derive(Serialize)]
pub struct InviteResponse {
    pub code: String,
    pub url: String,
    pub room_name: String,
    pub expires_at: Option<i64>,
    pub max_uses: Option<i32>,
}

pub async fn create_invite(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(body): Json<CreateInviteRequest>,
) -> Result<Json<InviteResponse>, AppError> {
    let user_id = authenticate(&headers, &state)?;

    let room = db::get_room_by_id(state.db.pool(), room_id)
        .await?
        .ok_or_else(|| AppError::NotFound("room not found".into()))?;

    // Only members can create invites
    db::get_member_role(state.db.pool(), room.id, user_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("only room members can create invite links".into()))?;

    let code = generate_short_code();
    let expires_at = body
        .expires_in_hours
        .map(|h| Utc::now() + chrono::Duration::hours(h as i64));

    let invite = db::create_invite(
        state.db.pool(),
        room.id,
        &code,
        user_id,
        body.max_uses,
        expires_at,
    )
    .await?;

    let base_url = &state.config.base_url;
    Ok(Json(InviteResponse {
        url: format!("{}/join/{}", base_url, invite.code),
        code: invite.code,
        room_name: room.name,
        expires_at: invite.expires_at.map(|t| t.timestamp()),
        max_uses: invite.max_uses,
    }))
}

#[derive(Serialize)]
pub struct RedeemResponse {
    pub room_id: String,
    pub room_name: String,
    pub joined: bool,
}

pub async fn redeem_invite(
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
    headers: HeaderMap,
) -> Result<Json<RedeemResponse>, AppError> {
    let user_id = authenticate(&headers, &state)?;

    let invite = db::get_invite_by_code(state.db.pool(), &code)
        .await?
        .ok_or_else(|| AppError::NotFound("invite link not found or expired".into()))?;

    // Check expiry
    if let Some(expires_at) = invite.expires_at {
        if Utc::now() > expires_at {
            return Err(AppError::Forbidden("this invite link has expired".into()));
        }
    }

    // Check max uses
    if let Some(max) = invite.max_uses {
        if invite.use_count >= max {
            return Err(AppError::Forbidden(
                "this invite link has reached its maximum uses".into(),
            ));
        }
    }

    let room = db::get_room_by_id(state.db.pool(), invite.room_id)
        .await?
        .ok_or_else(|| AppError::NotFound("room no longer exists".into()))?;

    // Check if already a member
    let already_member = db::get_member_role(state.db.pool(), room.id, user_id)
        .await?
        .is_some();

    if !already_member {
        db::add_room_member(state.db.pool(), room.id, user_id, db::MemberRole::Publisher).await?;
        db::increment_invite_use(state.db.pool(), invite.id).await?;
    }

    Ok(Json(RedeemResponse {
        room_id: room.id.to_string(),
        room_name: room.name,
        joined: !already_member,
    }))
}

fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<uuid::Uuid, AppError> {
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

fn generate_short_code() -> String {
    const CHARS: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";
    let mut rng = rand::rng();
    (0..7)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}
