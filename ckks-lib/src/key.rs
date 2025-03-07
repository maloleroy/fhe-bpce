use crate::{config::Config, polynomial::Polynomial};
use fhe_core::{
    f64::round,
    rand::distributions::{Distribution, Gaussian, Truncated, Uniform},
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
        let u = Uniform::<i64>::new(-1..=1);

        let coeffs = (0..config.degree())
            // Generate random coefficients in {-1, 0, 1}
            .map(|_| u.sample().unwrap())
            .collect();
        SecretKey {
            p: Polynomial::new(coeffs, 1.0),
        }
    };

    let pkey = {
        #[allow(clippy::range_minus_one)]
        let u = Uniform::<i64>::new(0..=config.modulus() - 1);

        let p1 = {
            let coeffs = (0..config.degree())
                // Generate random coefficients in {0, 1, ..., q-1}
                .map(|_| u.sample().unwrap())
                .collect();
            Polynomial::new(coeffs, 1.0)
        };

        let p0 = {
            let g = Gaussian::new(config.gdp().mu(), config.gdp().sigma());
            let beta = config.gdp().beta();
            let t = Truncated::new(g, -beta..=beta);

            let coeffs = skey
                .p
                .coeffs()
                .iter()
                .zip(p1.coeffs())
                .map(|(&sk, &r)| {
                    // Gaussian distribution bounded by beta
                    let e = t.sample().unwrap();
                    -r * sk + round(e)
                })
                .collect();
            Polynomial::new(coeffs, 1.0)
        };

        PublicKey { p0, p1 }
    };

    (pkey, skey)
}
