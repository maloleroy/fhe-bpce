use crate::{config::Config, polynomial::Polynomial};
use fhe_core::rand::rand_range;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
pub struct PublicKey {
    p0: Polynomial,
    p1: Polynomial,
}

impl PublicKey {
    #[must_use]
    #[inline]
    /// Encrypt a plaintext
    pub const fn p0(&self) -> &Polynomial {
        &self.p0
    }

    #[must_use]
    #[inline]
    /// Encrypt a plaintext
    pub const fn p1(&self) -> &Polynomial {
        &self.p1
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    p: Polynomial,
}

impl SecretKey {
    #[must_use]
    #[inline]
    /// Encrypt a plaintext
    pub const fn p(&self) -> &Polynomial {
        &self.p
    }
}

#[must_use]
/// Generate a fresh pair of keys
///
/// # Panics
///
/// Panics if randomness fails to be generated
pub fn generate_keys(config: Config) -> (PublicKey, SecretKey) {
    let skey = {
        let coeffs = (0..config.degree())
            .map(|_| rand_range::<i64>(1..100).unwrap())
            .collect();
        SecretKey {
            p: Polynomial::new(coeffs, 1.0),
        }
    };

    let pkey = {
        let p1 = {
            let coeffs = (0..config.degree())
                .map(|_| rand_range::<i64>(1..100).unwrap())
                .collect();
            Polynomial::new(coeffs, 1.0)
        };

        let p0 = {
            let coeffs = skey
                .p
                .coeffs()
                .iter()
                .zip(p1.coeffs())
                .map(|(&sk, &r)| -sk * r + rand_range::<i64>(-10..10).unwrap())
                .collect();
            Polynomial::new(coeffs, 1.0)
        };

        PublicKey { p0, p1 }
    };

    (pkey, skey)
}
