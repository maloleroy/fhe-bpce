//! CKKS Backend
#![warn(clippy::nursery, clippy::pedantic)]
#![forbid(unsafe_code)]

#[macro_use(vec)]
extern crate alloc;

pub mod cipher;
pub mod config;
pub mod key;
pub mod ops;
mod polynomial;

/// Type for plaintext values
pub type Plaintext = f64;
