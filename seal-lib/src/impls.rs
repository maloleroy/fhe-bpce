use sealy::{Ciphertext, Plaintext, RelinearizationKey};

#[must_use]
#[inline]
pub fn homom_add(
    evaluator: &impl sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    lhs: &Ciphertext,
    rhs: &Ciphertext,
) -> Ciphertext {
    evaluator.add(lhs, rhs).unwrap()
}

#[must_use]
#[inline]
pub fn homom_add_plain(
    evaluator: &impl sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    lhs: &Ciphertext,
    rhs: &Plaintext,
) -> Ciphertext {
    evaluator.add_plain(lhs, rhs).unwrap()
}

#[inline]
pub fn homom_add_inplace(
    evaluator: &impl sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    lhs: &mut Ciphertext,
    rhs: &Ciphertext,
) {
    evaluator.add_inplace(lhs, rhs).unwrap();
}

#[inline]
pub fn homom_add_plain_inplace(
    evaluator: &impl sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    lhs: &mut Ciphertext,
    rhs: &Plaintext,
) {
    evaluator.add_plain_inplace(lhs, rhs).unwrap();
}

#[must_use]
#[inline]
pub fn homom_mul(
    evaluator: &impl sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    lhs: &Ciphertext,
    rhs: &Ciphertext,
) -> Ciphertext {
    evaluator.multiply(lhs, rhs).unwrap()
}

#[must_use]
#[inline]
pub fn homom_mul_plain(
    evaluator: &impl sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    lhs: &Ciphertext,
    rhs: &Plaintext,
) -> Ciphertext {
    evaluator.multiply_plain(lhs, rhs).unwrap()
}

#[inline]
pub fn homom_mul_inplace(
    evaluator: &impl sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    lhs: &mut Ciphertext,
    rhs: &Ciphertext,
) {
    evaluator.multiply_inplace(lhs, rhs).unwrap();
}

#[inline]
pub fn homom_mul_plain_inplace(
    evaluator: &impl sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    lhs: &mut Ciphertext,
    rhs: &Plaintext,
) {
    evaluator.multiply_plain_inplace(lhs, rhs).unwrap();
}

#[must_use]
#[inline]
pub fn homom_exp(
    evaluator: &impl sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    base: &Ciphertext,
    exponent: u64,
    relin_key: &RelinearizationKey,
) -> Ciphertext {
    evaluator.exponentiate(base, exponent, relin_key).unwrap()
}

#[inline]
pub fn resize(
    _evaluator: &impl sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    _ciphertext: &mut Ciphertext,
) {
    todo!("resize");
    // TODO: implement resize
}

#[must_use]
#[inline]
pub fn relinearize(
    evaluator: &impl sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    ciphertext: &Ciphertext,
    relin_key: &RelinearizationKey,
) -> Ciphertext {
    evaluator.relinearize(ciphertext, relin_key).unwrap()
}
