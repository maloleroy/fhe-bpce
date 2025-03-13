//! Configuration module

pub enum Config {
    /// Cheon-Kim-Kim-Song scheme
    Ckks(seal_lib::context::CkksContext),
}
