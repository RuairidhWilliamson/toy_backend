pub mod string;

use arrayvec::ArrayString;
use chrono::NaiveDateTime;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use string::SecretString;

pub type UserId = i64;
pub type Username = ArrayString<80>;
pub type Password = SecretString<80>;

pub type SessionId = uuid::Uuid;
pub type SessionToken = SecretString<256>;

#[derive(Deserialize, JsonSchema)]
pub struct CreateUser {
    pub username: Username,
    pub password: Password,
}

#[derive(Serialize, JsonSchema)]
pub struct User {
    pub id: UserId,
    pub username: Username,
}

#[derive(Deserialize, JsonSchema)]
pub struct LoginRequest {
    pub username: Username,
    pub password: Password,
}

#[derive(Serialize, JsonSchema)]
pub enum LoginResponse {
    Success { session: Session },
    BadUsername,
    BadPassword,
}

#[derive(Serialize, JsonSchema)]
pub struct Session {
    pub id: SessionId,
    #[serde(serialize_with = "crate::string::exposer")]
    pub token: SessionToken,
    pub expires_at: NaiveDateTime,
}

#[derive(Serialize, JsonSchema)]
pub struct MyProfile {
    pub session_id: SessionId,
    pub user_id: UserId,
    pub username: Username,
}
