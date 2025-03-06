//! CKKS Backend
#![cfg_attr(not(test), no_std)]
#![warn(clippy::nursery, clippy::pedantic)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg_attr(test, macro_use(vec))]
extern crate alloc;

pub mod cipher;
pub mod config;
pub mod key;
pub mod ops;
mod polynomial;

pub type Plaintext = f64;
