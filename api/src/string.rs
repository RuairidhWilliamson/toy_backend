use std::borrow::Cow;

use arrayvec::ArrayString;
use schemars::{
    schema::{InstanceType, SchemaObject},
    JsonSchema,
};
use secrecy::{ExposeSecret, SecretBox};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SecretString<const N: usize>(SecretBox<ArrayString<N>>);

impl<const N: usize> JsonSchema for SecretString<N> {
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

impl<const N: usize> ExposeSecret<str> for SecretString<N> {
    fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}
