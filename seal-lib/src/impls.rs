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

#[inline]
pub fn homom_add_inplace(
    evaluator: &dyn sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    lhs: &mut Ciphertext,
    rhs: &Ciphertext,
) {
    evaluator.add_inplace(lhs, rhs).unwrap()
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

#[inline]
pub fn homom_mul_inplace(
    evaluator: &dyn sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    lhs: &mut Ciphertext,
    rhs: &Ciphertext,
) {
    evaluator.multiply_inplace(lhs, rhs).unwrap()
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

#[must_use]
#[inline]
pub fn resize(
    _evaluator: &dyn sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    _ciphertext: &mut Ciphertext,
) {
    // TODO: implement resize
}

#[must_use]
#[inline]
pub fn relinearize(
    evaluator: &dyn sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    ciphertext: &mut Ciphertext,
    relin_key: &RelinearizationKey,
) -> Ciphertext {
    evaluator.relinearize(ciphertext, relin_key).unwrap()
}
