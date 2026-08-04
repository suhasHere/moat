use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::db::{self, MemberRole, RoomVisibility};
use crate::error::AppError;
use crate::AppState;

#[derive(Deserialize, ToSchema)]
pub struct CreateRoomRequest {
    pub name: String,
    pub namespace_prefix: String,
    pub visibility: Option<RoomVisibility>,
    pub creator_id: Option<Uuid>,
}

#[utoipa::path(
    post,
    path = "/v1/rooms",
    request_body = CreateRoomRequest,
    responses(
        (status = 200, description = "Room created", body = db::Room),
    ),
    tag = "rooms"
)]
pub async fn create_room(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateRoomRequest>,
) -> Result<Json<db::Room>, AppError> {
    let visibility = body.visibility.unwrap_or(RoomVisibility::Public);
    let room =
        db::create_room(state.db.pool(), &body.name, &body.namespace_prefix, visibility).await?;

    if let Some(creator_id) = body.creator_id {
        let _ = db::add_room_member(state.db.pool(), room.id, creator_id, MemberRole::Admin).await;
    }

    Ok(Json(room))
}

#[utoipa::path(
    get,
    path = "/v1/rooms",
    responses(
        (status = 200, description = "List of rooms", body = Vec<db::Room>),
    ),
    tag = "rooms"
)]
pub async fn list_rooms(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<db::Room>>, AppError> {
    let rooms = db::list_rooms(state.db.pool()).await?;
    Ok(Json(rooms))
}

#[utoipa::path(
    get,
    path = "/v1/rooms/{room_id}",
    params(("room_id" = Uuid, Path, description = "Room UUID")),
    responses(
        (status = 200, description = "Room details", body = db::Room),
        (status = 404, description = "Room not found"),
    ),
    tag = "rooms"
)]
pub async fn get_room(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<Uuid>,
) -> Result<Json<db::Room>, AppError> {
    let room = db::get_room_by_id(state.db.pool(), room_id)
        .await?
        .ok_or_else(|| AppError::NotFound("room not found".into()))?;
    Ok(Json(room))
}

#[derive(Deserialize, ToSchema)]
pub struct AddMemberRequest {
    pub user_id: Uuid,
    pub role: MemberRole,
}

#[utoipa::path(
    post,
    path = "/v1/rooms/{room_id}/members",
    params(("room_id" = Uuid, Path, description = "Room UUID")),
    request_body = AddMemberRequest,
    responses(
        (status = 200, description = "Member added", body = db::RoomMember),
        (status = 404, description = "Room not found"),
    ),
    tag = "rooms"
)]
pub async fn add_member(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<Uuid>,
    Json(body): Json<AddMemberRequest>,
) -> Result<Json<db::RoomMember>, AppError> {
    db::get_room_by_id(state.db.pool(), room_id)
        .await?
        .ok_or_else(|| AppError::NotFound("room not found".into()))?;

    let member = db::add_room_member(state.db.pool(), room_id, body.user_id, body.role).await?;
    Ok(Json(member))
}

#[utoipa::path(
    get,
    path = "/v1/rooms/{room_id}/members",
    params(("room_id" = Uuid, Path, description = "Room UUID")),
    responses(
        (status = 200, description = "List of members", body = Vec<db::RoomMember>),
    ),
    tag = "rooms"
)]
pub async fn list_members(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<Uuid>,
) -> Result<Json<Vec<db::RoomMember>>, AppError> {
    let members = db::list_room_members(state.db.pool(), room_id).await?;
    Ok(Json(members))
}

#[utoipa::path(
    delete,
    path = "/v1/rooms/{room_id}/members/{user_id}",
    params(
        ("room_id" = Uuid, Path, description = "Room UUID"),
        ("user_id" = Uuid, Path, description = "User UUID"),
    ),
    responses(
        (status = 200, description = "Member removed"),
        (status = 404, description = "Member not found"),
    ),
    tag = "rooms"
)]
pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    Path((room_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let removed = db::remove_room_member(state.db.pool(), room_id, user_id).await?;
    if !removed {
        return Err(AppError::NotFound("member not found".into()));
    }
    Ok(Json(serde_json::json!({"removed": true})))
}
