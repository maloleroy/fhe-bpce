//! Polynomial backend for fast operations in CKKS contexts
#![allow(clippy::cast_precision_loss)] // For casting i64 to f64
use crate::Plaintext;
use alloc::vec::Vec;
use fhe_core::{
    f64::{round, round_to},
    rand::rand_range,
};
use zeroize::Zeroize;

pub type Coeff = i64;

#[derive(Debug, Clone, Zeroize)]
/// Polynomial backend struct for CKKS operations
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
    /// Constructor to create a new cyclotomic Polynomial with given coefficients
    ///
    /// # Panics
    ///
    /// Panics if n is not a power of two.
    pub fn cyclotomic(n: usize) -> Self {
        assert_eq!(n.count_ones(), 1, "n must be a power of 2");

        let mut coeffs = vec![0; n + 1];
        coeffs[0] = 1;
        coeffs[n] = 1;

        Self::new(coeffs, 1.0)
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
        let max_len = self.coeffs.len().max(other.coeffs.len());
        let mut result = Vec::with_capacity(max_len);

        // Add coefficients of both polynomials
        for i in 0..max_len {
            let a = self.coeffs.get(i).copied().unwrap_or(0);
            let b = other.coeffs.get(i).copied().unwrap_or(0);
            let to_push = if self.scale() >= other.scale() {
                a + round(b as f64 * (self.scale() / other.scale()))
            } else {
                round(a as f64 * (other.scale() / self.scale())) + b
            };
            result.push(to_push);
        }

        Self::new(result, self.scale().max(other.scale()))
    }

    #[must_use = "This method does not modify the polynomial, it returns a new one instead"]
    /// Polynomial subtraction
    pub fn subtract(&self, other: &Self) -> Self {
        let max_len = self.coeffs.len().max(other.coeffs.len());
        let mut result = Vec::with_capacity(max_len);

        // Add coefficients of both polynomials
        for i in 0..max_len {
            let a = self.coeffs.get(i).copied().unwrap_or(0);
            let b = other.coeffs.get(i).copied().unwrap_or(0);
            let to_push = if self.scale() >= other.scale() {
                a - round(b as f64 * (self.scale() / other.scale()))
            } else {
                round(a as f64 * (other.scale() / self.scale())) - b
            };
            result.push(to_push);
        }

        Self::new(result, self.scale().max(other.scale()))
    }

    #[must_use = "This method does not modify the polynomial, it returns a new one instead"]
    /// Polynomial multiplication
    pub fn multiply(&self, other: &Self) -> Self {
        let max_degree = self.coeffs.len() + other.coeffs.len() - 1;
        let mut result = vec![0; max_degree];

        for i in 0..self.coeffs.len() {
            for j in 0..other.coeffs.len() {
                result[i + j] += self.coeffs()[i] * other.coeffs()[j];
            }
        }

        Self::new(result, self.scale() * other.scale())
    }

    #[must_use = "This method does not modify the polynomial, it returns a new one instead"]
    /// Coefficient by coefficient multiplication
    pub fn multiply_coeff(&self, other: &Self) -> Self {
        let max_scale = self.scale().max(other.scale());
        let min_scale = self.scale().min(other.scale());

        let result_coeffs = self
            .coeffs()
            .iter()
            .zip(other.coeffs().iter())
            .map(|(a, b)| round((*a as f64 * *b as f64) / min_scale) as _)
            .collect();

        // Create a new polynomial with rounded coefficients
        Self::new(result_coeffs, max_scale)
    }

    #[must_use = "This method does not modify the polynomial, it returns a new one instead"]
    /// Divide the coefficient by coefficient
    pub fn divide_factor(&self, rhs: f64) -> Self {
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
    /// Remainder of polynomial division
    pub fn rem(&self, rhs: &Self) -> Self {
        fn compute_degree(coeffs: &[Coeff]) -> usize {
            let mut i = coeffs.len();
            while i > 0 && coeffs[i - 1] == 0 {
                i -= 1;
            }
            i
        }

        let mut self_coeffs = self.coeffs().to_vec();
        let mut self_degree = compute_degree(self.coeffs());
        let rhs_degree = compute_degree(rhs.coeffs());

        while self_degree >= rhs_degree {
            let shift = self_degree - rhs_degree;
            let factor = self_coeffs[self_degree - 1] / rhs.coeffs()[rhs_degree - 1];

            for i in 0..rhs_degree {
                self_coeffs[shift + i] -= rhs.coeffs()[i] * factor;
            }

            self_coeffs[self_degree - 1] = 0;
            self_degree = compute_degree(&self_coeffs);
        }

        Self::new(self_coeffs, self.scale())
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
