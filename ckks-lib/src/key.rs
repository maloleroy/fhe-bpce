use crate::{config::Config, polynomial::Polynomial};
use fhe_core::{
    f64::round,
    rand::{rand_gaussian_truncated, rand_range},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
/// Public key
pub struct PublicKey {
    p0: Polynomial,
    p1: Polynomial,
}

impl PublicKey {
    #[must_use]
    #[inline]
    pub const fn p0(&self) -> &Polynomial {
        &self.p0
    }

    #[must_use]
    #[inline]
    pub const fn p1(&self) -> &Polynomial {
        &self.p1
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
/// Secret key
///
/// # Notes
///
/// The key is automatically zeroized when it goes out of scope
pub struct SecretKey {
    p: Polynomial,
}

impl SecretKey {
    #[must_use]
    #[inline]
    pub const fn p(&self) -> &Polynomial {
        &self.p
    }
}

#[must_use]
/// Generate a fresh pair of keys
///
/// # Panics
///
/// Panics if randomness fails to be generated, or if any noise value is non-positive
pub fn generate_keys(config: Config) -> (PublicKey, SecretKey) {
    let skey = {
        let coeffs = (0..config.degree())
            // Generate random coefficients in {-1, 0, 1}
            .map(|_| rand_range::<i64>(-1..2).unwrap())
            .collect();
        SecretKey {
            p: Polynomial::new(coeffs, 1.0),
        }
    };

    let pkey = {
        let p1 = {
            let coeffs = (0..config.degree())
                // Generate random coefficients in {0, 1, ..., q-1}
                .map(|_| rand_range::<i64>(0..config.modulus()).unwrap())
                .collect();
            Polynomial::new(coeffs, 1.0)
        };

        let p0 = {
            let coeffs = skey
                .p
                .coeffs()
                .iter()
                .zip(p1.coeffs())
                .map(|(&sk, &r)| {
                    // Gaussian distribution bounded by beta
                    let e = rand_gaussian_truncated(
                        config.gdp().mu(),
                        config.gdp().sigma(),
                        config.gdp().beta(),
                    )
                    .unwrap();
                    -r * sk + round(e)
                })
                .collect();
            Polynomial::new(coeffs, 1.0)
        };

        PublicKey { p0, p1 }
    };

    (pkey, skey)
}
