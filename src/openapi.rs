use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::{Modify, OpenApi};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Moat — MoQ Auth Token Service",
        version = "0.1.0",
        description = "Authentication, room management, and scoped token minting for Media over QUIC (MoQ) relays.",
        license(name = "MIT OR Apache-2.0"),
    ),
    paths(
        crate::routes::auth::guest_login,
        crate::routes::auth::google_login,
        crate::routes::token::mint_token,
        crate::routes::token::mint_anonymous,
        crate::routes::rooms::create_room,
        crate::routes::rooms::list_rooms,
        crate::routes::rooms::get_room,
        crate::routes::rooms::add_member,
        crate::routes::rooms::list_members,
        crate::routes::rooms::remove_member,
        crate::routes::invites::create_invite,
        crate::routes::invites::redeem_invite,
        crate::routes::privacypass::challenge,
        crate::routes::privacypass::token_request_proxy,
    ),
    components(schemas(
        crate::routes::auth::GuestLoginRequest,
        crate::routes::auth::AuthResponse,
        crate::routes::token::MintTokenRequest,
        crate::routes::token::MintTokenResponse,
        crate::routes::token::MintTokenScope,
        crate::routes::token::AnonTokenRequest,
        crate::routes::token::AnonTokenResponse,
        crate::routes::token::AnonTokenScope,
        crate::routes::rooms::CreateRoomRequest,
        crate::routes::rooms::AddMemberRequest,
        crate::routes::invites::CreateInviteRequest,
        crate::routes::invites::InviteResponse,
        crate::routes::invites::RedeemResponse,
        crate::routes::privacypass::ChallengeRequest,
        crate::routes::privacypass::ChallengeResponse,
        crate::db::Room,
        crate::db::RoomMember,
        crate::db::RoomVisibility,
        crate::db::MemberRole,
        crate::token::TokenRole,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "auth", description = "Authentication (guest login, Google OAuth)"),
        (name = "token", description = "Scoped MoQ access token minting"),
        (name = "rooms", description = "Room CRUD and membership management"),
        (name = "invites", description = "Invite link creation and redemption"),
        (name = "privacypass", description = "Privacy Pass challenge and token issuance (RFC 9578)"),
    )
)]
pub struct ApiDoc;

impl ApiDoc {
    pub fn spec() -> utoipa::openapi::OpenApi {
        <Self as OpenApi>::openapi()
    }
}

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_default();
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
        );
    }
}
