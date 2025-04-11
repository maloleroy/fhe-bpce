//! Data loading utilities.
#![allow(dead_code)]

pub mod csv;
pub mod json;
#[cfg(feature = "parquet")]
pub mod parquet;

use bincode::Encode;
use fhe_core::api::CryptoSystem;
use fhe_operations::seq_ops::SeqOpsData;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DataError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parsing error")]
    Parsing,
    #[error("Unsupported format")]
    UnsupportedFormat,
    #[error("Unknown error")]
    Unknown,
}

pub type DataResult<T> = Result<T, DataError>;

pub trait DataLoader<C: CryptoSystem>
where
    C::Operation2: Encode,
    C::Ciphertext: Encode,
{
    fn load(file: std::fs::File, cs: &C) -> DataResult<SeqOpsData<C>>;
}
