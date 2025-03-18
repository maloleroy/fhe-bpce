//! CKKS Backend
#![warn(clippy::nursery, clippy::pedantic)]
#![forbid(unsafe_code)]

mod selectable_collection;
mod sign;

pub use selectable_collection::{Flag, SelectableCollection, SelectableItem};
pub use sign::sign;