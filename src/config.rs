//! Configuration module

#[derive(Debug)]
pub enum Config<const P: i64, const N: u32> {
    /// Cheon-Kim-Kim-Song scheme
    Ckks(ckks_lib::config::Config<P, N>),
}
