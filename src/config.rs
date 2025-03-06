//! Configuration module

pub enum Config {
    /// Cheon-Kim-Kim-Song scheme
    Ckks(ckks_lib::config::Config),
}
