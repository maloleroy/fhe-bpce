//! CKKS Backend
#![warn(clippy::nursery, clippy::pedantic)]
#![forbid(unsafe_code)]

mod selectable_collection;
mod sign;

pub use fhe_core::api::select::Flag;
pub use selectable_collection::{SelectableCollection, SelectableItem};
pub use sign::sign;
