use super::CryptoSystem;

/// A `CryptoSystem` that can be used to perform selection operations.
pub trait SelectableCS: CryptoSystem {
    fn flag_to_plaintext(&self, flag: Flag) -> Self::Plaintext;
}

/// A flag that can be used to select items.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flag {
    On,
    Off,
}
