use std::path::Path;
use thiserror::Error;
use toml::Table;

pub struct ClientConfig {
    // TODO: Remove
    _foo: String,
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to load configuration file: {0}")]
    LoadError(#[from] tokio::io::Error),
    #[error("Failed to parse configuration file: {0}")]
    ParseError(#[from] toml::de::Error),
    #[error("Missing key in configuration file: {0}")]
    MissingKey(&'static str),
}

impl ClientConfig {
    pub async fn load_config(config_file: &Path) -> Result<Self, ConfigError> {
        let file = tokio::fs::read(config_file)
            .await
            .map_err(ConfigError::LoadError)?;
        let str_file = std::str::from_utf8(&file).map_err(|e| {
            ConfigError::LoadError(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;

        let table = str_file.parse::<Table>().map_err(ConfigError::ParseError)?;

        #[allow(clippy::disallowed_names)] // Test!
        let foo = table
            .get("foo")
            .ok_or(ConfigError::MissingKey("foo"))?
            .as_str()
            .unwrap()
            .to_string();

        Ok(Self { _foo: foo })
    }
}
