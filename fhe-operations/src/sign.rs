use fhe_core::api::CryptoSystem;

#[inline]
pub fn sign<C: CryptoSystem<Plaintext = f64>>(
    x: &C::Ciphertext,
    cs: &C,
    add_op: C::Operation2,
    mul_op: C::Operation2,
) -> C::Ciphertext
where
    C::Operation2: Copy,
{
    sign_pbas(x, cs, add_op, mul_op)
}

#[allow(dead_code)]
fn sign_hardcoded<C: CryptoSystem<Plaintext = f64>>(
    x: &C::Ciphertext,
    cs: &C,
    add_op: C::Operation2,
    mul_op: C::Operation2,
) -> C::Ciphertext
where
    C::Operation2: Copy,
{
    const A1: f64 = 1.211_324_865_405_185;
    const A3: f64 = -0.845_299_461_620_75;
    let a1 = cs.cipher(&A1);
    let a3 = cs.cipher(&A3);

    let x2 = cs.operate2(mul_op, x, x);
    let a3x2 = cs.operate2(mul_op, &a3, &x2);
    let a1_plus_a3x2 = cs.operate2(add_op, &a1, &a3x2);

    cs.operate2(mul_op, x, &a1_plus_a3x2)
}

fn sign_pbas<C: CryptoSystem<Plaintext = f64>>(
    x: &C::Ciphertext,
    cs: &C,
    add_op: C::Operation2,
    mul_op: C::Operation2,
) -> C::Ciphertext
where
    C::Operation2: Copy,
{
    const N: usize = 3;
    const COEFFS: [f64; N] = pbas_coefficients();
    let mut result = cs.cipher(&0.);
    let mut x_pow_i = cs.cipher(&1.);
    println!("Coeffs: {COEFFS:?}");
    for (i, coeff) in COEFFS.iter().enumerate().take(N) {
        // First we multiply the coefficient by the power of x
        let mut term = cs.cipher(coeff); // scale: basic
        term = cs.operate2(mul_op, &term, &x_pow_i); // TODO: use an in-place operation
        result = cs.operate2(add_op, &result, &term); // TODO: use an in-place operation
        if i != N - 1 {
            x_pow_i = cs.operate2(mul_op, &x_pow_i, x); // TODO: use an in-place operation
        }
    }
    result
}

#[allow(clippy::missing_panics_doc, dead_code)] // Panic is related to internal const `N`
fn sign_chebychev<C: CryptoSystem<Plaintext = f64>>(
    x: &C::Ciphertext,
    cs: &C,
    add_op: C::Operation2,
    mul_op: C::Operation2,
) -> C::Ciphertext
where
    C::Operation2: Copy,
{
    // use the chebychev polynomial to sign the ciphertext
    const N: usize = 10;
    const COEFFS: [i64; N] = chebyshev_coefficients::<N>();
    let mut result = cs.cipher(&0.);
    let mut x_pow_i = cs.cipher(&1.);
    for (i, coeff) in COEFFS.iter().enumerate().take(N) {
        assert!(
            i64::BITS - coeff.abs().leading_zeros() < f64::MANTISSA_DIGITS + coeff.trailing_zeros()
        );
        #[allow(clippy::cast_precision_loss)]
        let mut term = cs.cipher(&(*coeff as f64));
        term = cs.operate2(mul_op, &term, &x_pow_i); // TODO: use an in-place operation
        println!("after term (*): {i:?}");
        cs.relinearize(&mut term);
        println!("after term (=): {i:?}");
        // cs.relinearize(&mut result);
        // println!("after result (=): {:?}", i);
        result = cs.operate2(add_op, &result, &term); // TODO: use an in-place operation
        println!("after result (+): {i:?}");
        if i != N - 1 {
            x_pow_i = cs.operate2(mul_op, &x_pow_i, x); // TODO: use an in-place operation
            cs.relinearize(&mut x_pow_i);
            println!("after x_pow (=): {i:?}");
        }
    }
    result
}

/// Approximate sin(x) using a Taylor series expansion (valid for small x)
///
/// sin(x) = x - x^3/3! + x^5/5! - x^7/7! + x^9/9! ...
const fn sin_taylor(x: f64) -> f64 {
    let x2 = x * x;
    let x4 = x2 * x2;
    x * (1.0 - x2 / 6.0 + x4 / 120.0 - (x2 * x4) / 5040.0 + (x4 * x4) / 362_880.0)
}

#[allow(clippy::cast_precision_loss)]
/// Computes the denominator for the Lagrange basis polynomial
const fn denominator(i: usize, n: usize) -> f64 {
    let i_theta = (i as f64 * std::f64::consts::PI) / (n as f64 + 3.0);
    sin_taylor(i_theta)
}

/// Computes the coefficients of the PBAS polynomial for an odd `n`
const fn pbas_coefficients<const N: usize>() -> [f64; N] {
    let mut coeffs = [0.0; N];
    let mut i = 1;
    while i <= /*(N + 1) / 2*/ N {
        let den = denominator(i, N);
        let mut prod = 1.0;
        let mut j = 1;
        while j <= (N + 1).div_ceil(2) {
            if j != i {
                let num = denominator(j, N) * denominator(j, N);
                let den_sq = den * den - num;
                prod *= den_sq;
            }
            j += 1;
        }
        coeffs[i - 1] = 1.0 / den / prod;
        i += 1;
    }
    coeffs
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
    use fhe_core::{
        api::{Arity2Operation, Operation},
        f64::approx_eq,
    };

    #[derive(Clone)]
    struct TestCiphertext {
        // Absolutely not secure system, just for testing purposes.
        data: f64,
    }

    struct TestCryptoSystem {}

    #[derive(Clone, Copy, Debug)]
    enum Op {
        Add,
        Mul,
    }
    impl Operation for Op {}
    impl Arity2Operation for Op {}

    impl CryptoSystem for TestCryptoSystem {
        type Plaintext = f64;
        type Ciphertext = TestCiphertext;
        type Operation1 = ();
        type Operation2 = Op;

        fn cipher(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
            TestCiphertext {
                data: plaintext.clone(),
            }
        }
        fn decipher(&self, ciphertext: &Self::Ciphertext) -> Self::Plaintext {
            ciphertext.data.clone()
        }

        fn operate1(
            &self,
            _operation: Self::Operation1,
            lhs: &Self::Ciphertext,
        ) -> Self::Ciphertext {
            TestCiphertext {
                data: lhs.data.clone(),
            }
        }

        fn operate2(
            &self,
            operation: Self::Operation2,
            lhs: &Self::Ciphertext,
            rhs: &Self::Ciphertext,
        ) -> Self::Ciphertext {
            match operation {
                Op::Add => TestCiphertext {
                    data: lhs.data + rhs.data,
                },
                Op::Mul => TestCiphertext {
                    data: lhs.data * rhs.data,
                },
            }
        }

        fn relinearize(&self, _ciphertext: &mut Self::Ciphertext) {}
    }

    #[test]
    #[ignore]
    fn test_sign() {
        let cs = TestCryptoSystem {};

        let two = cs.cipher(&2.);
        let result = sign(&two, &cs, Op::Add, Op::Mul);
        assert!(approx_eq(cs.decipher(&result), 2., 1e-4));
    }
}
