use anyhow::{Context as _, anyhow};
use secrecy::{SecretString, zeroize::Zeroizing};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Secrets {
    pub password_pepper: SecretString,
}

impl Secrets {
    pub fn load() -> anyhow::Result<Self> {
        let path = std::env::var("SECRETS_PATH").unwrap_or_else(|_| "secrets.json".to_owned());
        let contents = Zeroizing::new(
            std::fs::read_to_string(&path).with_context(|| format!("could not open {path:?}"))?,
        );
        serde_json::from_str(&contents).map_err(|_| {
            anyhow!("error deserializing secrets config: error not shown for security")
        })
    }
}
