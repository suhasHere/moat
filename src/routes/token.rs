use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::db::{self, RoomVisibility};
use crate::error::AppError;
use crate::routes::auth::verify_session_token;
use crate::token::{MintRequest, TokenRole};
use crate::AppState;
use chrono::Utc;

#[derive(Deserialize)]
pub struct MintTokenRequest {
    pub room_id: String,
    pub role: Option<TokenRole>,
}

#[derive(Serialize, ToSchema)]
pub struct MintTokenResponse {
    pub token: String,
    pub expires_at: u64,
    pub scopes: Vec<MintTokenScope>,
    pub dpop: bool,
}

#[derive(Serialize, ToSchema)]
pub struct MintTokenScope {
    pub actions: Vec<String>,
    pub namespace: String,
}

#[utoipa::path(
    post,
    path = "/v1/token",
    request_body = MintTokenRequest,
    responses(
        (status = 200, description = "Token minted successfully", body = MintTokenResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Room not found"),
    ),
    security(("bearer" = [])),
    tag = "token"
)]
pub async fn mint_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<MintTokenRequest>,
) -> Result<Json<MintTokenResponse>, AppError> {
    let user_id = authenticate(&headers, &state)?;

    // Look up room by UUID or name (like anonymous endpoint)
    let room = if let Ok(room_id) = Uuid::parse_str(&body.room_id) {
        db::get_room_by_id(state.db.pool(), room_id).await?
    } else {
        db::get_room_by_name(state.db.pool(), &body.room_id).await?
    }
    .ok_or_else(|| AppError::NotFound("room not found".into()))?;

    // Enforce visibility rules
    let existing_role = db::get_member_role(state.db.pool(), room.id, user_id).await?;
    let member_role = match (room.visibility, existing_role) {
        // Already a member — always allowed
        (_, Some(role)) => role,
        // Private rooms require explicit membership
        (RoomVisibility::Private, None) => {
            return Err(AppError::Forbidden(
                "this is a private room — you need an invite link or to be added by a member"
                    .into(),
            ));
        }
        // Public or authenticated — auto-join as admin (can request any role)
        (_, None) => {
            db::add_room_member(state.db.pool(), room.id, user_id, db::MemberRole::Admin)
                .await?;
            db::MemberRole::Admin
        }
    };

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

    let expires_at = Utc::now().timestamp() as u64 + minted.expires_in;

    let actions = match token_role {
        TokenRole::PubSub => vec!["publish".into(), "subscribe".into()],
        TokenRole::Publisher => vec!["publish".into()],
        TokenRole::Subscriber => vec!["subscribe".into()],
    };

    Ok(Json(MintTokenResponse {
        token: minted.token,
        expires_at,
        scopes: vec![MintTokenScope {
            actions,
            namespace: room.namespace_prefix,
        }],
        dpop: false,
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct AnonTokenRequest {
    /// Room ID (UUID) or room name
    pub room_id: String,
    pub role: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AnonTokenResponse {
    pub token: String,
    pub expires_at: u64,
    pub scopes: Vec<AnonTokenScope>,
    pub dpop: bool,
}

#[derive(Serialize, ToSchema)]
pub struct AnonTokenScope {
    pub actions: Vec<String>,
    pub namespace: String,
}

#[utoipa::path(
    post,
    path = "/v1/token/anonymous",
    request_body = AnonTokenRequest,
    responses(
        (status = 200, description = "Anonymous token minted", body = AnonTokenResponse),
        (status = 403, description = "Room does not allow anonymous access"),
        (status = 404, description = "Room not found"),
    ),
    tag = "token"
)]
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

    // Guests can only join public rooms
    match room.visibility {
        RoomVisibility::Authenticated => {
            return Err(AppError::Forbidden(
                "this room requires sign-in — please log in with your identity provider to join".into(),
            ));
        }
        RoomVisibility::Private => {
            return Err(AppError::Forbidden(
                "this is a private room — you need an invite link or to be added by a member"
                    .into(),
            ));
        }
        RoomVisibility::Public => {}
    }

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
