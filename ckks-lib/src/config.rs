use crate::polynomial::Coeff;

#[derive(Debug, Clone, Copy)]
/// CKKS configuration parameters
pub struct Config {
    /// Polynomial degree (N)
    degree: usize,
    /// Modulus (q)
    modulus: Coeff,
    /// Parameters for the Gaussian Distribution
    gdp: Gdp,
}

impl Config {
    #[must_use]
    #[inline]
    /// Constructor to create a new Config
    pub const fn new(degree: usize, modulus: Coeff, gdp: Gdp) -> Self {
        Self {
            degree,
            modulus,
            gdp,
        }
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

    #[must_use]
    #[inline]
    /// Get the set of parameters for the Gaussian Distribution
    pub const fn gdp(&self) -> Gdp {
        self.gdp
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
/// Sets of parameters for the Gaussian Distribution
pub enum Gdp {
    /// Set of parameters advised by the Homomorphic Encryption Standard
    Tc128,
}

impl Gdp {
    #[must_use]
    #[inline]
    pub const fn mu(&self) -> f64 {
        match self {
            Self::Tc128 => 0.0,
        }
    }

    #[must_use]
    #[inline]
    pub const fn sigma(&self) -> f64 {
        use core::f64::consts::{FRAC_2_SQRT_PI, SQRT_2};

        match self {
            // 8 / sqrt(2 * pi)
            Self::Tc128 => 4.0 * FRAC_2_SQRT_PI / SQRT_2,
        }
    }

    #[must_use]
    #[inline]
    pub const fn beta(&self) -> f64 {
        match self {
            // round(6 * sigma)
            Self::Tc128 => 19.0,
        }
    }
}
