use fhe_core::api::CryptoSystem;

#[allow(clippy::missing_panics_doc)] // Panic is related to internal const `N`
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
    const COEFFS: [i64; N] = chebyshev_coefficients::<N>();
    let mut result = cs.cipher(&0.);
    let mut x_pow_i = cs.cipher(&1.);
    for (i, coeff) in COEFFS.iter().enumerate().take(N) {
        assert!(*coeff < (1 << f64::MANTISSA_DIGITS));
        #[allow(clippy::cast_precision_loss)]
        let mut term = cs.cipher(&(*coeff as f64));
        term = cs.operate(mul_op, &term, Some(&x_pow_i)); // TODO: use an in-place operation
        println!("after term (*): {:?}", i);
        cs.relinearize(&mut term);
        println!("after term (=): {:?}", i);
        // cs.relinearize(&mut result);
        // println!("after result (=): {:?}", i);
        result = cs.operate(add_op, &result, Some(&term)); // TODO: use an in-place operation
        println!("after result (+): {:?}", i);
        if i != N - 1 {
            x_pow_i = cs.operate(mul_op, &x_pow_i, Some(x)); // TODO: use an in-place operation
            cs.relinearize(&mut x_pow_i);
            println!("after x_pow (=): {:?}", i);
        }
    }
    result
}

const fn chebyshev_coefficients<const N: usize>() -> [i64; N] {
    let mut coeffs = [[0; N]; N];
    coeffs[0][0] = 1;
    if N > 1 {
        coeffs[1][1] = 1;
    }

    let mut i = 2;
    while i < N {
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

    coeffs[N - 1]
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
            SealCkksContext::new(DegreeType::D4096, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);

        let two = cs.cipher(&2.);
        let result = sign(&two, &cs, CkksHOperation::Add, CkksHOperation::Mul);
        assert!(approx_eq(cs.decipher(&result), 2., 1e-4));
    }
}
