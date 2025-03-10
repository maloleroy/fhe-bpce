use crate::polynomial::Coeff;

#[derive(Debug, Clone, Copy)]
/// CKKS configuration parameters
pub struct Config {
    /// Polynomial degree (N)
    ///
    /// `degree` is a power of two
    degree: usize,
    /// Modulus (q)
    modulus: Coeff,
    /// Parameters for the Gaussian Distribution
    gdp: GaussianDistribParams,
}

impl Config {
    #[must_use]
    #[inline]
    /// Constructor to create a new Config
    ///
    /// # Panics
    ///
    /// Panics if the degree is not a power of 2
    pub const fn new(degree: usize, modulus: Coeff, gdp: GaussianDistribParams) -> Self {
        assert!(degree.is_power_of_two(), "degree must be a power of 2");
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
    /// Get the degree parameter as a power of two.
    pub const fn degree_as_power_of_two(&self) -> u32 {
        self.degree.trailing_zeros()
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
    pub const fn gdp(&self) -> GaussianDistribParams {
        self.gdp
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
/// Sets of parameters for the Truncated Gaussian Distribution
///
/// There are three parameters: mean, standard deviation, and bounds.
///
/// The constant `Self::TC128` is the set of parameters advised by security experts.
pub struct GaussianDistribParams {
    /// Mean
    mu: f64,
    /// Standard deviation
    sigma: f64,
    /// Bounds
    beta: f64,
}

impl GaussianDistribParams {
    /// Set of parameters advised by security experts
    pub const TC128: Self = Self {
        mu: 0.0,
        // 8 / sqrt(2 * pi)
        sigma: 4.0 * core::f64::consts::FRAC_2_SQRT_PI / core::f64::consts::SQRT_2,
        // round(6 * sigma)
        beta: 19.0,
    };

    #[must_use]
    #[inline]
    /// Returns the mean
    pub const fn mu(&self) -> f64 {
        self.mu
    }

    #[must_use]
    #[inline]
    // Sigma sigma boy sigma boy
    /// Returns the standard deviation
    pub const fn sigma(&self) -> f64 {
        self.sigma
    }

    #[must_use]
    #[inline]
    /// Returns the beta parameter,
    /// i.e. the bound for the truncated Gaussian distribution
    pub const fn beta(&self) -> f64 {
        self.beta
    }
}
