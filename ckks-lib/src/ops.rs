use crate::{
    Plaintext,
    cipher::{Ciphertext, Encryptor},
    polynomial::Polynomial,
};

impl Encryptor {
    #[must_use]
    #[inline]
    /// Perform homomorphic addition
    pub fn homomorphic_add(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Ciphertext {
        let raw_sum0 = Polynomial::add(&lhs.c0, &rhs.c0);
        let raw_sum1 = Polynomial::add(&lhs.c1, &rhs.c1);
        Ciphertext {
            c0: Polynomial::mod_reduce(&raw_sum0, self.config().modulus()),
            c1: Polynomial::mod_reduce(&raw_sum1, self.config().modulus()),
        }
    }

    #[must_use]
    #[inline]
    /// Perform homomorphic division
    pub fn homomorphic_div_plain(&self, lhs: &Ciphertext, rhs: Plaintext) -> Ciphertext {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cipher::Decryptor,
        config::{Config, Gdp},
        key::generate_keys,
    };

    #[test]
    fn homomorphic_add() {
        // FIXME: It often fails
        const PRECISION: f64 = 1e-1;

        let config = Config::new(4096, 1_000_000_007, Gdp::Tc128);
        let (pkey, skey) = generate_keys(config);

        let encryptor = Encryptor::new(pkey, config);
        let decryptor = Decryptor::new(skey, config);

        let lhs = encryptor.encrypt(&[1.0, 2.0, 3.0, 4.0], 1e7);
        let rhs = encryptor.encrypt(&[5.0, 6.0, 7.0, 8.0], 1e7);

        let sum = encryptor.homomorphic_add(&lhs, &rhs);
        let decrypted = decryptor.decrypt(&sum);

        println!("decrypted: {:?}", decrypted);
        for (p, d) in decrypted.iter().zip([6.0, 8.0, 10.0, 12.0].iter()) {
            assert!((p - d).abs() < PRECISION);
        }
    }
}
