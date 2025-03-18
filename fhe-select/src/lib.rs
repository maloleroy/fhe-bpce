//! CKKS Backend
#![warn(clippy::nursery, clippy::pedantic)]
#![forbid(unsafe_code)]
#![feature(generic_const_exprs)]

mod selectable_collection;
mod sign;

pub use selectable_collection::{Flag, SelectableCollection, SelectableItem};
pub use sign::sign;