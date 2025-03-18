use fhe_core::api::CryptoSystem;

pub fn sign<C: CryptoSystem<Plaintext = f64>>(
    x: &C::Ciphertext,
    cs: &C,
    add_op: C::Operation,
    mul_op: C::Operation,
) -> C::Ciphertext
where
    C::Operation: Copy,
{
    // use the chebychev polynomial to sign the ciphertext
    const N: usize = 10;
    const COEFFS: [i64; N + 1] = chebyshev_coefficients::<N>();
    let mut result = cs.cipher(&0.);
    let mut x_pow_i = cs.cipher(&1.);
    for i in 0..=N {
        let mut term = cs.cipher(&(COEFFS[i] as f64));
        term = cs.operate(mul_op, &term, Some(&x_pow_i)); // TODO: use an in-place operation
        result = cs.operate(add_op, &result, Some(&term)); // TODO: use an in-place operation
        if i != N {
            x_pow_i = cs.operate(mul_op, &x_pow_i, Some(&x)); // TODO: use an in-place operation
        }
    }
    result
}

const fn chebyshev_coefficients<const N: usize>() -> [i64; N + 1] {
    let mut coeffs = [[0; N + 1]; N + 1];
    coeffs[0][0] = 1;
    if N > 0 {
        coeffs[1][1] = 1;
    }

    let mut i = 2;
    while i <= N {
        let mut j = 0;
        while j < i {
            coeffs[i][j + 1] += 2 * coeffs[i - 1][j];
            if j < coeffs[i - 2].len() {
                coeffs[i][j] -= coeffs[i - 2][j];
            }
            j += 1;
        }
        i += 1;
    }

    coeffs[N]
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe_core::f64::approx_eq;
    use seal_lib::{
        CkksHOperation, DegreeType, SealCkksCS, SecurityLevel, context::SealCkksContext,
    };

    #[test]
    fn test_sign() {
        let context: SealCkksContext =
            SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);

        let two = cs.cipher(&2.);
        let result = sign(&two, &cs, CkksHOperation::Add, CkksHOperation::Mul);
        assert!(approx_eq(cs.decipher(&result), 2., 1e-4));
    }
}
