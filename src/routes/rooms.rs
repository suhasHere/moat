use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::db::{self, MemberRole, RoomVisibility};
use crate::error::AppError;
use crate::AppState;

#[derive(Deserialize)]
pub struct CreateRoomRequest {
    pub name: String,
    pub namespace_prefix: String,
    pub visibility: Option<RoomVisibility>,
    pub creator_id: Option<Uuid>,
}

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

pub async fn list_rooms(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<db::Room>>, AppError> {
    let rooms = db::list_rooms(state.db.pool()).await?;
    Ok(Json(rooms))
}

pub async fn get_room(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<Uuid>,
) -> Result<Json<db::Room>, AppError> {
    let room = db::get_room_by_id(state.db.pool(), room_id)
        .await?
        .ok_or_else(|| AppError::NotFound("room not found".into()))?;
    Ok(Json(room))
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub user_id: Uuid,
    pub role: MemberRole,
}

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

pub async fn list_members(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<Uuid>,
) -> Result<Json<Vec<db::RoomMember>>, AppError> {
    let members = db::list_room_members(state.db.pool(), room_id).await?;
    Ok(Json(members))
}

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
