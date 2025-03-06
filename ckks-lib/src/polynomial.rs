//! Polynomial backend for fast operations in CKKS contexts
use crate::Plaintext;
use alloc::vec::Vec;
use fhe_core::{
    f64::{round, round_to},
    rand::rand_range,
};
use zeroize::Zeroize;

pub type Coeff = i64;

#[derive(Debug, Clone, Zeroize)]
pub struct Polynomial {
    /// Coefficients for the polynomial
    coeffs: Vec<Coeff>,
    scale: f64,
}

impl Polynomial {
    #[must_use]
    #[inline]
    /// Constructor to create a new Polynomial with given coefficients
    pub const fn new(coeffs: Vec<Coeff>, scale: f64) -> Self {
        Self { coeffs, scale }
    }

    #[must_use]
    #[inline]
    /// Get the coefficients of the polynomial
    pub fn coeffs(&self) -> &[Coeff] {
        &self.coeffs
    }

    #[must_use]
    #[inline]
    /// Get the scale of the polynomial
    pub const fn scale(&self) -> f64 {
        self.scale
    }

    #[must_use = "This method does not modify the polynomial, it returns a new one instead"]
    /// Polynomial addition
    pub fn add(&self, other: &Self) -> Self {
        // TODO: Scale accordingly
        assert_eq!(self.scale(), other.scale());

        let max_len = self.coeffs.len().max(other.coeffs.len());
        let mut result = Vec::with_capacity(max_len);

        // Add coefficients of both polynomials
        for i in 0..max_len {
            let a = self.coeffs.get(i).copied().unwrap_or(0);
            let b = other.coeffs.get(i).copied().unwrap_or(0);
            result.push(a + b);
        }

        Self::new(result, self.scale())
    }

    #[must_use = "This method does not modify the polynomial, it returns a new one instead"]
    /// Polynomial subtraction
    pub fn subtract(&self, other: &Self) -> Self {
        // TODO: Scale accordingly
        assert_eq!(self.scale(), other.scale());

        let max_len = self.coeffs.len().max(other.coeffs.len());
        let mut result = Vec::with_capacity(max_len);

        // Add coefficients of both polynomials
        for i in 0..max_len {
            let a = self.coeffs.get(i).copied().unwrap_or(0);
            let b = other.coeffs.get(i).copied().unwrap_or(0);
            result.push(a - b);
        }

        Self::new(result, self.scale())
    }

    #[must_use = "This method does not modify the polynomial, it returns a new one instead"]
    /// Coefficient by coefficient multiplication
    pub fn multiply_coeff(&self, other: &Self) -> Self {
        // TODO: Scale accordingly
        assert_eq!(self.scale(), other.scale());

        let result_coeffs = self
            .coeffs()
            .iter()
            .zip(other.coeffs().iter())
            .map(|(a, b)| round((*a as f64 * *b as f64) / self.scale()) as _)
            .collect();

        // Create a new polynomial with rounded coefficients
        Self::new(result_coeffs, self.scale())
    }

    #[must_use = "This method does not modify the polynomial, it returns a new one instead"]
    /// Divide the coefficient by coefficient
    pub fn divide_coeff(&self, rhs: f64) -> Self {
        let result_coeffs = self
            .coeffs()
            .iter()
            .map(|&coeff| round(coeff as f64 / rhs) as _)
            .collect();

        Self::new(result_coeffs, self.scale())
    }

    #[must_use = "This method does not modify the polynomial, it returns a new one instead"]
    /// Polynomial negation
    pub fn negation(&self) -> Self {
        let negated_coeffs = self.coeffs.iter().map(|&c| -c).collect();
        Self::new(negated_coeffs, self.scale())
    }

    #[must_use = "This method does not modify the polynomial, it returns a new one instead"]
    /// Modular reduction of coefficients
    pub fn mod_reduce(&self, modulus: Coeff) -> Self {
        let result_coeffs = self
            .coeffs()
            .iter()
            .map(|coeff| coeff % modulus)
            .filter(|&coeff| coeff != 0)
            .collect();

        Self::new(result_coeffs, self.scale())
    }

    /// Add noise to coefficients in place
    pub fn add_noise(&mut self, noise: i64) {
        self.coeffs
            .iter_mut()
            .for_each(|coeff| *coeff += rand_range(-noise..noise).unwrap());
    }

    #[must_use]
    /// Encodes a series of plaintext values into a polynomial
    pub fn encode(plaintext: &[Plaintext], scale: f64) -> Self {
        let coeffs = plaintext.iter().map(|&x| round(x * scale)).collect();
        Self::new(coeffs, scale)
    }

    #[must_use]
    /// Decodes a polynomial back to plaintext values
    pub fn decode(&self) -> Vec<Plaintext> {
        /// Threshold for considering values as zero
        const TRESHOLD: f64 = 1e-10;
        /// Number of decimal places for rounding
        const DECIMAL_PLACES: u16 = 3;

        self.coeffs
            .iter()
            .map(|&c| {
                let raw = c as f64 / self.scale();
                let rounded = round_to(raw, DECIMAL_PLACES);
                if rounded.abs() < TRESHOLD {
                    0.0
                } else {
                    rounded
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let poly1 = Polynomial::new(vec![1, 2, 3], 1.0);
        let poly2 = Polynomial::new(vec![3, 2, 1], 1.0);

        let result = poly1.add(&poly2);
        assert_eq!(result.coeffs(), &[4, 4, 4]);
    }

    #[test]
    fn test_subtract() {
        let poly1 = Polynomial::new(vec![1, 2, 3], 1.0);
        let poly2 = Polynomial::new(vec![3, 2, 1], 1.0);

        let result = poly1.subtract(&poly2);
        assert_eq!(result.coeffs(), &[-2, 0, 2]);
    }

    #[test]
    fn test_multiply_coeff() {
        let poly1 = Polynomial::new(vec![1, 2, 3], 1.0);
        let poly2 = Polynomial::new(vec![3, 2, 1], 1.0);

        let result = poly1.multiply_coeff(&poly2);
        assert_eq!(result.coeffs(), &[3, 4, 3]);
    }

    #[test]
    fn test_negation() {
        let poly = Polynomial::new(vec![1, 2, 3], 1.0);

        let result = poly.negation();
        assert_eq!(result.coeffs(), &[-1, -2, -3]);
    }

    #[test]
    fn test_mod_reduce() {
        let poly = Polynomial::new(vec![1, 2, 3, 4, 5], 1.0);

        let result = poly.mod_reduce(3);
        assert_eq!(result.coeffs(), &[1, 2, 1, 2]);
    }

    #[test]
    fn test_encode_decode() {
        let plaintext = vec![1.21, 2.0, 3.0];
        let scale = 10.0;

        let poly = Polynomial::encode(&plaintext, scale);
        assert_eq!(poly.coeffs(), &[12, 20, 30]);

        let decoded = poly.decode();
        assert_eq!(decoded, vec![1.2, 2.0, 3.0]);
    }
}
