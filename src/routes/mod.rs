pub mod auth;
mod rooms;
mod token;
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
        // Token minting
        .route("/v1/token", post(token::mint_token))
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
        // Web UI
        .route("/", get(web::index))
        .route("/app.js", get(web::app_js))
        .route("/style.css", get(web::style_css))
        // Health
        .route("/health", get(health))
}

async fn health() -> &'static str {
    "ok"
}
