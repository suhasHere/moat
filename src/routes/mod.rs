pub mod auth;
pub mod invites;
pub mod privacypass;
pub mod rooms;
pub mod token;
mod web;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use crate::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // Auth
        .route("/v1/auth/guest", post(auth::guest_login))
        .route("/v1/auth/google", post(auth::google_login))
        .route("/v1/auth/privacypass/challenge", post(privacypass::challenge))
        .route("/v1/auth/privacypass/token-request", post(privacypass::token_request_proxy))
        // Token minting
        .route("/v1/token", post(token::mint_token))
        .route("/v1/token/anonymous", post(token::mint_anonymous))
        // Room management
        .route("/v1/rooms", get(rooms::list_rooms).post(rooms::create_room))
        .route("/v1/rooms/:room_id", get(rooms::get_room))
        .route(
            "/v1/rooms/:room_id/members",
            get(rooms::list_members).post(rooms::add_member),
        )
        .route(
            "/v1/rooms/:room_id/members/:user_id",
            axum::routing::delete(rooms::remove_member),
        )
        // Invites
        .route(
            "/v1/rooms/:room_id/invites",
            post(invites::create_invite),
        )
        .route("/v1/invites/:code/redeem", post(invites::redeem_invite))
        // Landing page
        .route("/", get(web::landing))
        // Web UI (dashboard)
        .route("/app", get(web::index))
        .route("/app.js", get(web::app_js))
        .route("/style.css", get(web::style_css))
        // Health
        .route("/health", get(health))
}

async fn health() -> &'static str {
    "ok"
}
