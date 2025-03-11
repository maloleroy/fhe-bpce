use crate::{
    Plaintext,
    cipher::{Ciphertext, Encryptor, scaled::ScaledPolynomial},
};

impl<const P: i64, const N: u32> Encryptor<P, N> {
    #[must_use]
    #[inline]
    /// Perform homomorphic addition
    pub fn homomorphic_add(
        &self,
        lhs: &Ciphertext<P, N>,
        rhs: &Ciphertext<P, N>,
    ) -> Ciphertext<P, N> {
        Ciphertext {
            c0: ScaledPolynomial::add(&lhs.c0, &rhs.c0),
            c1: ScaledPolynomial::add(&lhs.c1, &rhs.c1),
        }
    }

    #[must_use]
    #[inline]
    /// Perform homomorphic division by a plaintext
    pub fn homomorphic_div_plain(
        &self,
        _lhs: &Ciphertext<P, N>,
        _rhs: Plaintext,
    ) -> Ciphertext<P, N> {
        todo!()
    }

    #[must_use]
    #[inline]
    /// Perform homomorphic multiplication
    pub fn homomorphic_multiplication(
        &self,
        _lhs: &Ciphertext<P, N>,
        _rhs: Plaintext,
    ) -> Ciphertext<P, N> {
        // This is in here that we will have to perform RESCALE
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cipher::Decryptor,
        config::{Config, GaussianDistribParams},
        key::generate_keys,
    };

    #[test]
    fn homomorphic_add() {
        // FIXME: It often fails
        const PRECISION: f64 = 1e-1;

        let config = Config::<1_000_000_007, 12>::new(GaussianDistribParams::TC128);
        let (pkey, skey) = generate_keys(config);

        let encryptor = Encryptor::new(pkey, config);
        let decryptor = Decryptor::new(skey, config);

        let lhs = encryptor.encrypt(&[1.0, 2.0, 3.0, 4.0], 1e7);
        let rhs = encryptor.encrypt(&[5.0, 6.0, 7.0, 8.0], 1e7);

        let sum = encryptor.homomorphic_add(&lhs, &rhs);
        let decrypted = decryptor.decrypt(&sum, 1e7);

        println!("decrypted: {:?}", decrypted);
        for (p, d) in decrypted.iter().zip([6.0, 8.0, 10.0, 12.0].iter()) {
            assert!((p - d).abs() < PRECISION);
        }
    }
}
