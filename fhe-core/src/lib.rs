//! Core utils for FHE.
#![cfg_attr(not(test), no_std)]
#![warn(clippy::nursery, clippy::pedantic)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod api;
pub mod f64;
pub mod rand;
