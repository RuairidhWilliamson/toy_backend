use std::borrow::Cow;

use arrayvec::ArrayString;
use schemars::{
    schema::{InstanceType, SchemaObject},
    JsonSchema,
};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

type TextChar255 = Box<ArrayString<255>>;

type Username = TextChar255;
type Password = ApiSecretString;

#[derive(Debug, Deserialize)]
pub struct ApiSecretString(SecretBox<str>);

impl JsonSchema for ApiSecretString {
    fn schema_name() -> String {
        "SecretString".to_owned()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        Cow::Borrowed(concat!(module_path!(), "::SecretString"))
    }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            format: None,
            ..Default::default()
        }
        .into()
    }
}

impl ExposeSecret<str> for ApiSecretString {
    fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

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
