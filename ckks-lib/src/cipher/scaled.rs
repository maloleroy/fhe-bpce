#![allow(clippy::cast_precision_loss)]

use fhe_core::{
    f64::{round, round_to},
    pring::{Coeff, Polynomial},
};

use crate::Plaintext;

/// A Polynomial encoding plaintexts scaled by a factor
pub struct ScaledPolynomial<const P: i64, const N: u32> {
    pub(crate) p: Polynomial<P, N>,
    pub(crate) scale: f64,
}

impl<const P: i64, const N: u32> ScaledPolynomial<P, N> {
    #[must_use]
    #[inline]
    /// Constructor to create a new `ScaledPolynomial`
    pub const fn new(p: Polynomial<P, N>, scale: f64) -> Self {
        Self { p, scale }
    }

    #[must_use]
    #[inline]
    /// Encode plaintexts into a `ScaledPolynomial`
    pub fn encode(p: &[Plaintext], scale: f64) -> Self {
        let coeffs = p.iter().map(|&x| round(x * scale)).collect();
        Self {
            p: Polynomial::new(coeffs),
            scale,
        }
    }

    #[must_use]
    #[inline]
    /// Decode the `ScaledPolynomial` into plaintexts
    pub fn decode(&self) -> Vec<Plaintext> {
        /// Threshold for considering values as zero
        const TRESHOLD: f64 = 1e-10;
        /// Number of decimal places for rounding
        const DECIMAL_PLACES: u16 = 3;

        self.p
            .coeffs()
            .iter()
            .map(|&c| {
                let raw = c.as_i64() as f64 / self.scale();
                let rounded = round_to(raw, DECIMAL_PLACES);
                if rounded.abs() < TRESHOLD {
                    0.0
                } else {
                    rounded
                }
            })
            .collect()
    }

    #[must_use]
    #[inline]
    /// Get the polynomial
    pub const fn polynomial(&self) -> &Polynomial<P, N> {
        &self.p
    }

    #[must_use]
    #[inline]
    /// Get the scale
    pub const fn scale(&self) -> f64 {
        self.scale
    }

    #[must_use]
    #[inline]
    /// Add two polynomials
    pub fn add(lhs: &Self, rhs: &Self) -> Self {
        let max_len = lhs.p.len().max(rhs.p.len());
        let mut coeffs = Vec::with_capacity(max_len);
        for i in 0..max_len {
            let l = lhs.p.coeffs().get(i).copied().unwrap_or(Coeff::new(0));
            let r = rhs.p.coeffs().get(i).copied().unwrap_or(Coeff::new(0));
            let to_push = if lhs.scale() >= rhs.scale() {
                round(l.as_i64() as f64 * (rhs.scale() / lhs.scale())) + r.as_i64()
            } else {
                l.as_i64() + round(r.as_i64() as f64 * (lhs.scale() / rhs.scale()))
            };
            coeffs.push(to_push);
        }
        Self {
            p: Polynomial::new(coeffs),
            scale: lhs.scale().min(rhs.scale()),
        }
    }

    #[must_use]
    #[inline]
    /// Substract two polynomials
    pub fn sub(lhs: &Self, rhs: &Self) -> Self {
        let max_len = lhs.p.len().max(rhs.p.len());
        let mut coeffs = Vec::with_capacity(max_len);
        for i in 0..max_len {
            let l = lhs.p.coeffs().get(i).copied().unwrap_or(Coeff::new(0));
            let r = rhs.p.coeffs().get(i).copied().unwrap_or(Coeff::new(0));
            let to_push = if lhs.scale() >= rhs.scale() {
                round(l.as_i64() as f64 * (rhs.scale() / lhs.scale())) - r.as_i64()
            } else {
                l.as_i64() - round(r.as_i64() as f64 * (lhs.scale() / rhs.scale()))
            };
            coeffs.push(to_push);
        }
        Self {
            p: Polynomial::new(coeffs),
            scale: lhs.scale().min(rhs.scale()),
        }
    }

    #[must_use]
    #[inline]
    /// Multiply two polynomials
    pub fn multiply(lhs: &Self, rhs: &Self) -> Self {
        let mut coeffs = Vec::<i64>::with_capacity(lhs.p.len() + rhs.p.len() - 1);
        for i in 0..lhs.p.len() {
            for j in 0..rhs.p.len() {
                let to_push =
                    round(lhs.p.coeffs()[i].as_i64() as f64 * rhs.p.coeffs()[j].as_i64() as f64);
                let idx = i + j;
                if idx < coeffs.len() {
                    coeffs[idx] = i64::try_from(
                        (i128::from(coeffs[idx]) + i128::from(to_push)).rem_euclid(i128::from(P)),
                    )
                    .unwrap();
                } else {
                    coeffs.push(to_push);
                }
            }
        }

        let p = Self {
            p: Polynomial::new(coeffs),
            scale: lhs.scale() * rhs.scale(),
        };
        p.rescale(lhs.scale().max(rhs.scale()))
    }

    fn rescale(self, scale: f64) -> Self {
        let coeffs = self
            .p
            .coeffs()
            .iter()
            .map(|&c| round(c.as_i64() as f64 / scale))
            .collect();

        let p = Polynomial::new(coeffs);
        Self {
            p,
            scale: self.scale() / scale,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    // Use example parameters for testing.
    const P: i64 = 10_000_000_007;
    const N: u32 = 12;
    const SCALE: f64 = 1e6;

    #[test]
    fn test_scaled_polynomial_new() {
        let coeffs = vec![1, 2, 3, 4, 5];
        let p = Polynomial::new(coeffs);

        let scaled_poly = ScaledPolynomial::<P, N>::new(p, SCALE);

        for (i, &c) in scaled_poly.polynomial().coeffs().iter().enumerate() {
            assert_eq!(c.as_i64(), i as i64 + 1);
        }
        assert_eq!(scaled_poly.scale(), SCALE);
    }

    #[test]
    fn test_scaled_polynomial_encode() {
        let plaintext: Vec<f64> = vec![1.234, 2.345, 3.456, 0.0, 5.678];

        let scaled_poly = ScaledPolynomial::<P, N>::encode(&plaintext, SCALE);

        for (i, &c) in scaled_poly.polynomial().coeffs().iter().enumerate() {
            assert_eq!(c.as_i64(), round(plaintext[i] * SCALE));
        }
        assert_eq!(scaled_poly.scale(), SCALE);
    }

    #[test]
    fn test_scaled_polynomial_decode() {
        let plaintext: Vec<f64> = vec![1.234, 2.3e-13, 3.456, 0.0, 5.678];
        let decoded = ScaledPolynomial::<P, N>::encode(&plaintext, SCALE).decode();
        let expected = vec![1.234, 0.0, 3.456, 0.0, 5.678];

        assert_eq!(decoded.len(), plaintext.len());
        for (orig, dec) in decoded.into_iter().zip(expected.into_iter()) {
            assert_eq!(orig, dec);
        }
    }

    #[test]
    fn test_scaled_polynomial_add() {
        let lhs = ScaledPolynomial::<P, N>::encode(&[1., 2., 3.], 20.);
        let rhs = ScaledPolynomial::<P, N>::encode(&[4., 5., 6.], 50.);

        let sum = ScaledPolynomial::<P, N>::add(&lhs, &rhs);

        let expected = ScaledPolynomial::<P, N>::encode(&[2.6, 4., 5.4], 20.);

        assert_eq!(sum.polynomial().coeffs(), expected.polynomial().coeffs());
        assert_eq!(sum.scale(), expected.scale());
    }

    #[test]
    fn test_encode_decode_round_trip() {
        // Arrange: Some sample plaintexts and a scaling factor.
        let plaintext: Vec<f64> = vec![1.234, 2.345, 3.456, 0.0, 5.678];

        // Act: Encode and then decode.
        let scaled_poly = ScaledPolynomial::<P, N>::encode(&plaintext, SCALE);
        let decoded = scaled_poly.decode();

        // Assert: Check that the decoded values match the originals within tolerance.
        assert_eq!(decoded.len(), plaintext.len());
        for (orig, dec) in plaintext.into_iter().zip(decoded.into_iter()) {
            assert!(
                (orig - dec).abs() < 1e-3,
                "Original {} differs from decoded {}",
                orig,
                dec
            );
        }
    }

    #[test]
    fn test_encode_and_decode_zero_threshold() {
        // Arrange: Values nearly zero (under decode's TRESHOLD) should decode to 0.0.
        let plaintext: Vec<f64> = vec![1e-11, 2.5e-11];

        // Act: Encode and decode.
        let scaled_poly = ScaledPolynomial::<P, N>::encode(&plaintext, SCALE);
        let decoded = scaled_poly.decode();

        // Assert: Values below the threshold become 0.0.
        for dec in decoded {
            assert_eq!(dec, 0.0);
        }
    }
}
