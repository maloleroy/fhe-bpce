use crate::Plaintext;
use crate::config::Config;
use crate::key::{PublicKey, SecretKey};
use alloc::vec::Vec;
use fhe_core::f64::round;
use fhe_core::pring::Polynomial;
use fhe_core::rand::distributions::{Distribution, Gaussian, Truncated, Uniform};
use scaled::ScaledPolynomial;

pub mod scaled;

/// Struct for CKKS encryption
pub struct Encryptor<const P: i64, const N: u32> {
    pkey: PublicKey<P, N>,
    config: Config<P, N>,
}

/// Struct for CKKS ciphertext
pub struct Ciphertext<const P: i64, const N: u32> {
    pub(crate) c0: ScaledPolynomial<P, N>,
    pub(crate) c1: ScaledPolynomial<P, N>,
}

impl<const P: i64, const N: u32> Encryptor<P, N> {
    #[must_use]
    #[inline]
    /// Constructor to create a new CKKS Encryptor
    pub const fn new(pkey: PublicKey<P, N>, config: Config<P, N>) -> Self {
        Self { pkey, config }
    }

    #[must_use]
    #[inline]
    /// Returns the configuration
    pub const fn config(&self) -> Config<P, N> {
        self.config
    }

    #[must_use]
    /// Encrypt plaintext values
    ///
    /// # Panics
    ///
    /// Panics if the scaling factor is not positive.
    pub fn encrypt(&self, plaintext: &[Plaintext], scale: f64) -> Ciphertext<P, N> {
        assert!(scale > 0.0, "Scaling factor must be positive");

        let encoded = ScaledPolynomial::encode(plaintext, scale);

        let u = {
            let u = Uniform::<i64>::new(-1..=1);
            Polynomial::random(u)
        };

        let e1 = {
            let g = Gaussian::new(self.config().gdp().mu(), self.config().gdp().sigma());
            let beta = self.config().gdp().beta();
            let t = Truncated::new(g, -beta..=beta);

            let coeffs = (0..N).map(|_| round(t.sample().unwrap())).collect();
            Polynomial::new(coeffs)
        };
        let e2 = {
            let g = Gaussian::new(self.config().gdp().mu(), self.config().gdp().sigma());
            let beta = self.config().gdp().beta();
            let t = Truncated::new(g, -beta..=beta);

            let coeffs = (0..N).map(|_| round(t.sample().unwrap())).collect();
            Polynomial::new(coeffs)
        };

        let c0 = {
            let pku = Polynomial::multiply(self.pkey.p0(), &u);
            let pku_e = Polynomial::add(&pku, &e1);
            Polynomial::add(&pku_e, &encoded.p)
        };

        let c1 = {
            let pku = Polynomial::multiply(self.pkey.p1(), &u);
            Polynomial::add(&pku, &e2)
        };

        Ciphertext {
            c0: ScaledPolynomial::new(c0, scale),
            c1: ScaledPolynomial::new(c1, scale),
        }
    }
}

/// Struct for CKKS decryption
pub struct Decryptor<const P: i64, const N: u32> {
    skey: SecretKey<P, N>,
    // config: Config<P, N>,
}

impl<const P: i64, const N: u32> Decryptor<P, N> {
    #[must_use]
    #[inline]
    /// Constructor to create a new CKKS Decryptor
    pub const fn new(skey: SecretKey<P, N>, _config: Config<P, N>) -> Self {
        Self { skey }
    }

    #[must_use]
    /// Decrypt ciphertext
    pub fn decrypt(&self, ciphertext: &Ciphertext<P, N>) -> Vec<Plaintext> {
        let c1sk = ScaledPolynomial::multiply(
            &ciphertext.c1,
            &ScaledPolynomial::new(self.skey.p().clone(), 1.0),
        );
        let encoded = ScaledPolynomial::add(&ciphertext.c0, &c1sk);
        encoded.decode()
    }
}

#[cfg(test)]
mod tests {
    use crate::config::GaussianDistribParams;

    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        // FIXME: It often fails
        const PRECISION: f64 = 5e-2;

        let config = Config::<1_000_000_000_007, 12>::new(GaussianDistribParams::TC128);
        let (pkey, skey) = crate::key::generate_keys(config);

        let encryptor = Encryptor::new(pkey, config);
        let decryptor = Decryptor::new(skey, config);

        let plaintext = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let ciphertext = encryptor.encrypt(&plaintext, 1e6);
        let decrypted = decryptor.decrypt(&ciphertext);

        for (p, d) in plaintext.iter().zip(decrypted.iter()) {
            println!("plaintex: {} ; decrypted: {}", p, d);
            assert!((p - d).abs() < PRECISION);
        }
    }
}
