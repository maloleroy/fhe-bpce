#[derive(
    Debug,
    Clone,
    PartialEq,
    bincode::Decode,
    bincode::Encode,
    zeroize::Zeroize,
    zeroize::ZeroizeOnDrop,
)]
#[non_exhaustive]
/// The different operations that can be performed on the ciphertexts.
pub enum Operation {
    Addition,
    Multiplication,
    AdditionPlain(f64),
    MultiplicationPlain(f64),
}
