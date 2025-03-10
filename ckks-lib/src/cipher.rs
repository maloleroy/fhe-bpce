use crate::Plaintext;
use crate::config::Config;
use crate::key::{PublicKey, SecretKey};
use crate::polynomial::Polynomial;
use alloc::vec::Vec;
use fhe_core::f64::round;
use fhe_core::rand::distributions::{Distribution, Gaussian, Truncated, Uniform};

/// Struct for CKKS encryption
pub struct Encryptor {
    pkey: PublicKey,
    config: Config,
}

/// Struct for CKKS ciphertext
pub struct Ciphertext {
    pub(crate) c0: Polynomial,
    pub(crate) c1: Polynomial,
}

impl Ciphertext {
    #[must_use]
    #[inline]
    pub const fn c0(&self) -> &Polynomial {
        &self.c0
    }

    #[must_use]
    #[inline]
    pub const fn c1(&self) -> &Polynomial {
        &self.c1
    }
}

impl Encryptor {
    #[must_use]
    #[inline]
    /// Constructor to create a new CKKS Encryptor
    pub const fn new(pkey: PublicKey, config: Config) -> Self {
        Self { pkey, config }
    }

    #[must_use]
    #[inline]
    /// Returns the configuration
    pub const fn config(&self) -> Config {
        self.config
    }

    #[must_use]
    /// Encrypt plaintext values
    ///
    /// # Panics
    ///
    /// Panics if the scaling factor is not positive.
    pub fn encrypt(&self, plaintext: &[Plaintext], scale: f64) -> Ciphertext {
        assert!(scale > 0.0, "Scaling factor must be positive");
        let encoded = Polynomial::encode(plaintext, scale);

        let u = {
            let u = Uniform::<i64>::new(-1..=1);

            let coeffs = (0..self.config().degree())
                .map(|_| u.sample().unwrap())
                .collect();
            Polynomial::new(coeffs, 1.0)
        };

        let e1 = {
            let g = Gaussian::new(self.config().gdp().mu(), self.config().gdp().sigma());
            let beta = self.config().gdp().beta();
            let t = Truncated::new(g, -beta..=beta);

            let coeffs = (0..self.config().degree())
                .map(|_| round(t.sample().unwrap()))
                .collect();
            Polynomial::new(coeffs, 1.0)
        };
        let e2 = {
            let g = Gaussian::new(self.config().gdp().mu(), self.config().gdp().sigma());
            let beta = self.config().gdp().beta();
            let t = Truncated::new(g, -beta..=beta);

            let coeffs = (0..self.config().degree())
                .map(|_| round(t.sample().unwrap()))
                .collect();
            Polynomial::new(coeffs, 1.0)
        };

        let c0 = {
            let pku = Polynomial::multiply_coeff(self.pkey.p0(), &u);
            let pkue = Polynomial::add(&pku, &e1);
            Polynomial::add(&pkue, &encoded)
        };

        let c1 = {
            let pku = Polynomial::multiply_coeff(self.pkey.p1(), &u);
            Polynomial::add(&pku, &e2)
        };

        Ciphertext { c0, c1 }
    }
}

/// Struct for CKKS decryption
pub struct Decryptor {
    skey: SecretKey,
    config: Config,
}

impl Decryptor {
    #[must_use]
    #[inline]
    /// Constructor to create a new CKKS Decryptor
    pub const fn new(skey: SecretKey, config: Config) -> Self {
        Self { skey, config }
    }

    #[must_use]
    /// Decrypt ciphertext
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Vec<Plaintext> {
        let c1sk_raw = Polynomial::multiply(ciphertext.c1(), self.skey.p());
        let c1sk = Polynomial::rem(&c1sk_raw, &Polynomial::cyclotomic(self.config.degree()));
        let encoded = Polynomial::add(ciphertext.c0(), &c1sk);
        Polynomial::decode(&encoded)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Gdp;

    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        // FIXME: It often fails
        const PRECISION: f64 = 5e-2;

        let config = Config::new(4096, 10_000_000_007, Gdp::Tc128);
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
