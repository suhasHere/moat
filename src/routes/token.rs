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
use chrono::Utc;

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

/// Anonymous token endpoint: creates a guest user, auto-joins the room, and mints a token.
/// Compatible with moq-chat's AnonymousStrategy: POST /v1/token/anonymous
#[derive(Deserialize)]
pub struct AnonTokenRequest {
    pub room_id: String,
    pub role: Option<String>,
}

#[derive(Serialize)]
pub struct AnonTokenResponse {
    pub token: String,
    pub expires_at: u64,
    pub scopes: Vec<AnonTokenScope>,
    pub dpop: bool,
}

#[derive(Serialize)]
pub struct AnonTokenScope {
    pub actions: Vec<String>,
    pub namespace: String,
}

pub async fn mint_anonymous(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AnonTokenRequest>,
) -> Result<Json<AnonTokenResponse>, AppError> {
    let guest_id = uuid::Uuid::new_v4();
    let display_name = format!("Guest-{}", &guest_id.to_string()[..8]);
    let email = format!("guest-{}@moat.local", &guest_id.to_string()[..8]);

    let user = db::upsert_user(
        state.db.pool(),
        &email,
        "guest",
        &guest_id.to_string(),
        Some(&display_name),
    )
    .await?;

    // Find room by ID or name
    let room = if let Ok(room_id) = Uuid::parse_str(&body.room_id) {
        db::get_room_by_id(state.db.pool(), room_id).await?
    } else {
        db::get_room_by_name(state.db.pool(), &body.room_id).await?
    }
    .ok_or_else(|| AppError::NotFound("room not found".into()))?;

    // Auto-join as pubsub (guests get full access for demo purposes)
    let role = match body.role.as_deref() {
        Some("publisher") => db::MemberRole::Publisher,
        Some("subscriber") => db::MemberRole::Subscriber,
        _ => db::MemberRole::Publisher, // default: pubsub for guests
    };
    db::add_room_member(state.db.pool(), room.id, user.id, role).await?;

    let token_role = match role {
        db::MemberRole::Publisher => TokenRole::PubSub,
        db::MemberRole::Subscriber => TokenRole::Subscriber,
        db::MemberRole::Admin => TokenRole::PubSub,
    };

    let namespace_parts: Vec<Vec<u8>> = room
        .namespace_prefix
        .split('/')
        .map(|s| s.as_bytes().to_vec())
        .collect();

    let minted = state.minter.mint(&MintRequest {
        subject: user.email,
        namespace_parts,
        role: token_role,
        lifetime_secs: state.config.token_lifetime_secs,
    })?;

    let expires_at = Utc::now().timestamp() as u64 + minted.expires_in;

    let actions = match token_role {
        TokenRole::PubSub => vec!["publish".into(), "subscribe".into()],
        TokenRole::Publisher => vec!["publish".into()],
        TokenRole::Subscriber => vec!["subscribe".into()],
    };

    Ok(Json(AnonTokenResponse {
        token: minted.token,
        expires_at,
        scopes: vec![AnonTokenScope {
            actions,
            namespace: room.namespace_prefix,
        }],
        dpop: false,
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
