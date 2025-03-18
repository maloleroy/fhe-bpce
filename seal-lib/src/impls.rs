use sealy::{Ciphertext, Plaintext, RelinearizationKey};

#[must_use]
#[inline]
pub fn homom_add(
    evaluator: &dyn sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    lhs: &Ciphertext,
    rhs: &Ciphertext,
) -> Ciphertext {
    evaluator.add(lhs, rhs).unwrap()
}

#[must_use]
#[inline]
pub fn homom_mul(
    evaluator: &dyn sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    lhs: &Ciphertext,
    rhs: &Ciphertext,
) -> Ciphertext {
    evaluator.multiply(lhs, rhs).unwrap()
}

#[must_use]
#[inline]
pub fn homom_exp(
    evaluator: &dyn sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    base: &Ciphertext,
    exponent: u64,
    relin_key: &RelinearizationKey,
) -> Ciphertext {
    evaluator.exponentiate(base, exponent, relin_key).unwrap()
}
