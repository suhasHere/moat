mod rooms;
mod token;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use crate::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/token", post(token::mint_token))
        .route("/v1/rooms", get(rooms::list_rooms).post(rooms::create_room))
        .route("/v1/rooms/{room_id}", get(rooms::get_room))
        .route(
            "/v1/rooms/{room_id}/members",
            get(rooms::list_members).post(rooms::add_member),
        )
        .route(
            "/v1/rooms/{room_id}/members/{user_id}",
            axum::routing::delete(rooms::remove_member),
        )
        .route("/health", get(health))
}

async fn health() -> &'static str {
    "ok"
}
