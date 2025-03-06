use crate::polynomial::Coeff;

#[derive(Debug, Clone, Copy)]
/// CKKS configuration parameters
pub struct Config {
    /// Polynomial degree (N)
    degree: usize,
    /// Modulus (q)
    modulus: Coeff,
}

impl Config {
    #[must_use]
    #[inline]
    /// Constructor to create a new Config
    pub const fn new(degree: usize, modulus: Coeff) -> Self {
        Self { degree, modulus }
    }

    #[must_use]
    #[inline]
    /// Get the degree parameter
    pub const fn degree(&self) -> usize {
        self.degree
    }

    #[must_use]
    #[inline]
    /// Get the modulus parameter
    pub const fn modulus(&self) -> Coeff {
        self.modulus
    }
}
