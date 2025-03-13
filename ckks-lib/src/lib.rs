//! CKKS Backend
#![warn(clippy::nursery, clippy::pedantic)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cipher;
pub mod config;
pub mod key;
pub mod ops;

/// Type for plaintext values
pub type Plaintext = f64;
