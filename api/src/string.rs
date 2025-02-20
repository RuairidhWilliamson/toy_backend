use std::borrow::Cow;

use arrayvec::ArrayString;
use schemars::{
    JsonSchema,
    schema::{InstanceType, SchemaObject},
};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serializer};

#[derive(Debug, Deserialize)]
pub struct SecretString<const N: usize>(SecretBox<ArrayString<N>>);

impl<const N: usize> SecretString<N> {
    pub fn new(s: &str) -> Self {
        let mut out = Box::new(ArrayString::<N>::new_const());
        out.push_str(s);
        Self(SecretBox::new(out))
    }
}

impl<const N: usize> JsonSchema for SecretString<N> {
    fn schema_name() -> String {
        "SecretString".to_owned()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        Cow::Borrowed(concat!(module_path!(), "::SecretString"))
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
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

pub fn exposer<const N: usize, S>(
    string: &SecretString<N>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(string.expose_secret())
}
