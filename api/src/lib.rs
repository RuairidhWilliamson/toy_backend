pub mod string;

use arrayvec::ArrayString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use string::SecretString;

type Username = ArrayString<255>;
type Password = SecretString<255>;

#[derive(Deserialize, JsonSchema)]
pub struct CreateUser {
    pub username: Username,
    pub password: Password,
}

#[derive(Serialize, JsonSchema)]
pub struct User {
    pub id: i64,
    pub username: Username,
}

#[derive(Deserialize, JsonSchema)]
pub struct LoginRequest {
    pub username: Username,
    pub password: Password,
}

#[derive(Serialize, JsonSchema)]
pub enum LoginResponse {
    Success,
    Failure,
}
