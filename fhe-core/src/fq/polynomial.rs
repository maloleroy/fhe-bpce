use alloc::vec::Vec;

use super::FqInt64;

pub struct FqPolynomial<const Q: usize> {
    coeffs: Vec<FqInt64<Q>>,
}

impl<const Q: usize> FqPolynomial<Q> {
    #[must_use]
    #[inline]
    /// Constructor to create a new FqPolynomial with given coefficients
    pub const fn new(coeffs: Vec<FqInt64<Q>>) -> Self {
        Self { coeffs }
    }

    #[must_use]
    #[inline]
    /// Get the coefficients of the FqPolynomial
    pub fn coeffs(&self) -> &[FqInt64<Q>] {
        &self.coeffs
    }

    #[must_use = "This method does not modify the FqPolynomial, it returns a new one instead"]
    /// FqPolynomial addition
    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.coeffs.len().max(other.coeffs.len());
        let mut result = Vec::with_capacity(max_len);

        // Add coefficients of both polynomials
        for i in 0..max_len {
            let a = self.coeffs.get(i).copied().unwrap_or(FqInt64::default());
            let b = other.coeffs.get(i).copied().unwrap_or(FqInt64::default());
            result.push(a + b);
        }

        Self::new(result)
    }

    #[must_use = "This method does not modify the FqPolynomial, it returns a new one instead"]
    /// FqPolynomial subtraction
    pub fn sub(&self, other: &Self) -> Self {
        let max_len = self.coeffs.len().max(other.coeffs.len());
        let mut result = Vec::with_capacity(max_len);

        // Subtract coefficients of both polynomials
        for i in 0..max_len {
            let a = self.coeffs.get(i).copied().unwrap_or(FqInt64::default());
            let b = other.coeffs.get(i).copied().unwrap_or(FqInt64::default());
            result.push(a - b);
        }

        Self::new(result)
    }
}
