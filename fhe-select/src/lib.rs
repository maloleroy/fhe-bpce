//! CKKS Backend
#![warn(clippy::nursery, clippy::pedantic)]
#![forbid(unsafe_code)]

mod selectable_collection;

pub use selectable_collection::{FLAG_OFF, FLAG_ON, SelectableCollection, SelectableItem};
