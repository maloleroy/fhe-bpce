use std::path::{Path, PathBuf};
use thiserror::Error;
use toml::Table;

#[derive(Debug)]
pub struct ClientConfig {
    data: PathBuf,
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to load configuration file: {0}")]
    LoadError(#[from] tokio::io::Error),
    #[error("Failed to parse configuration file: {0}")]
    ParseError(#[from] toml::de::Error),
    #[error("Missing key in configuration file: {0}")]
    MissingKey(&'static str),
    #[error("Invalid value in configuration file: {0}")]
    InvalidValue(&'static str),
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
        let data = table
            .get("data")
            .ok_or(ConfigError::MissingKey("data"))?
            .as_str()
            .ok_or(ConfigError::InvalidValue("data"))?
            .to_string()
            .into();

        Ok(Self { data })
    }

    #[must_use]
    #[inline]
    #[allow(clippy::missing_const_for_fn)] // False positive
    pub fn data(&self) -> &Path {
        &self.data
    }
}
