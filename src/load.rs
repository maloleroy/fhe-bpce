//! Data loading utilities.
#![allow(dead_code)]

pub mod bytes;
pub mod csv;
pub mod json;
#[cfg(feature = "parquet")]
pub mod parquet;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DataError {
    #[error("IO error: {0}")]
    Io(#[from] tokio::io::Error),
    #[error("Unsupported format")]
    UnsupportedFormat,
    #[error("Unknown error")]
    Unknown,
}

pub type DataResult<T> = Result<T, DataError>;

pub trait DataLoader<T> {
    async fn load(file: tokio::fs::File) -> DataResult<T>;
}
