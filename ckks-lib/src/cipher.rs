use crate::Plaintext;
use crate::config::Config;
use crate::key::{PublicKey, SecretKey};
use crate::polynomial::Polynomial;
use alloc::vec::Vec;

/// Struct for CKKS encryption
pub struct Encryptor {
    pkey: PublicKey,
    config: Config,
}

pub struct Ciphertext(pub(crate) Polynomial);

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

        let coeffs = encoded
            .coeffs()
            .iter()
            .zip(self.pkey.p0().coeffs())
            .zip(self.pkey.p1().coeffs())
            .map(|((&e, &pk0), &pk1)| e + pk0 * pk1)
            .collect();
        let p = Polynomial::new(coeffs, encoded.scale());

        Ciphertext(Polynomial::mod_reduce(&p, self.config.modulus()))
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
        // FIXME: Do we have to do this?
        let reduced_poly = Polynomial::mod_reduce(&ciphertext.0, self.config.modulus());

        let decrypted_poly: Vec<i64> = reduced_poly
            .coeffs()
            .iter()
            .zip(self.skey.p().coeffs())
            .map(|(&c, &sk)| c - sk)
            .collect();
        let decrypted_polynomial = Polynomial::new(decrypted_poly, ciphertext.0.scale());

        Polynomial::decode(&decrypted_polynomial)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        // FIXME: It often fails
        const PRECISION: f64 = 5e-2;

        let config = Config::new(2048, 100_000_007);
        let (pkey, skey) = crate::key::generate_keys(config);

        let encryptor = Encryptor::new(pkey, config);
        let decryptor = Decryptor::new(skey, config);

        let plaintext = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let ciphertext = encryptor.encrypt(&plaintext, 1.0);
        let decrypted = decryptor.decrypt(&ciphertext);

        for (p, d) in plaintext.iter().zip(decrypted.iter()) {
            assert!((p - d).abs() < PRECISION);
        }
    }
}
