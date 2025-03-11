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
                    coeffs[idx] += to_push.rem_euclid(P);
                    coeffs[idx] = coeffs[idx].rem_euclid(P);
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
