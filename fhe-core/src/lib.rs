//! Core utils for FHE.
#![cfg_attr(not(test), no_std)]
#![warn(clippy::nursery, clippy::pedantic)]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Re-export of a Finite Field maths crate.
pub mod f64;
pub mod rand;
