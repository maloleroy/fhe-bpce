use sealy::{Ciphertext, Plaintext};

pub fn homom_add(
    evaluator: &dyn sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    lhs: &Ciphertext,
    rhs: &Ciphertext,
) -> Ciphertext {
    evaluator.add(lhs, rhs).unwrap()
}

pub fn homom_mul(
    evaluator: &dyn sealy::Evaluator<Plaintext = Plaintext, Ciphertext = Ciphertext>,
    lhs: &Ciphertext,
    rhs: &Ciphertext,
) -> Ciphertext {
    evaluator.multiply(lhs, rhs).unwrap()
}
