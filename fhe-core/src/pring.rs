//! Polynomial Ring Z/pZ[X]/(X^N + 1) where N is a power of 2 and p is prime.
use core::ops::{Add, Mul, Neg, Sub};

use alloc::vec::Vec;

use crate::rand::distributions::Distribution;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(::zeroize::Zeroize))]
#[repr(transparent)]
/// Coefficient of the polynomial, namely elements of Z/pZ
pub struct Coeff<const P: i64>(i64);

impl<const P: i64> Coeff<P> {
    #[must_use]
    #[inline]
    /// Constructor to create a new Coeff
    ///
    /// # Panics
    ///
    /// Panics if the modulus is not prime.
    pub const fn new(coeff: i64) -> Self {
        Self(coeff.rem_euclid(P))
    }

    #[must_use]
    #[inline]
    /// Constructor to create a new Coeff
    ///
    /// # Safety
    ///
    /// The given coefficient must be in the range [0, P).
    pub const unsafe fn new_unchecked(coeff: i64) -> Self {
        Self(coeff)
    }

    #[must_use]
    #[inline]
    /// Get the value of the coefficient
    pub const fn as_i64(self) -> i64 {
        self.0
    }
}

impl<const P: i64> Add for Coeff<P> {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self((self.0 + rhs.0).rem_euclid(P))
    }
}

impl<const P: i64> Sub for Coeff<P> {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self((self.0 - rhs.0).rem_euclid(P))
    }
}

impl<const P: i64> Mul for Coeff<P> {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self((self.0 * rhs.0).rem_euclid(P))
    }
}

impl<const P: i64> Neg for Coeff<P> {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        // We have 0 <= self.0 < P, so -P < -self.0 < 0
        // Thus, P - self.0 is the least nonnegative value
        // in the same equivalence class as -self.0
        Self(P - self.0)
    }
}

impl<const P: i64> From<Coeff<P>> for i64 {
    #[inline]
    fn from(coeff: Coeff<P>) -> Self {
        coeff.0
    }
}

#[derive(Debug, Clone, Eq)]
#[cfg_attr(feature = "zeroize", derive(::zeroize::Zeroize))]
/// Polynomial Ring Z/pZ[X]/(X^N + 1) where N is a power of 2 and p is prime.
pub struct Polynomial<const P: i64, const N: u32> {
    coeffs: Vec<Coeff<P>>,
}

impl<const P: i64, const N: u32> Polynomial<P, N> {
    const M: usize = 1 << N;

    #[must_use]
    #[inline]
    /// Constructor to create a new Polynomial
    pub fn new(coeffs: Vec<i64>) -> Self {
        let coeffs = coeffs.into_iter().map(Coeff::new).collect();
        let raw = Self { coeffs };
        raw.rem_cyclo()
    }

    #[must_use]
    /// Generate a random polynomial using a given distribution
    ///
    /// # Panics
    ///
    /// Panics if the distribution fails to generate randomness.
    pub fn random<D: Distribution>(d: &D) -> Self
    where
        D::Output: Into<i64>,
    {
        let coeffs = (0..Self::M)
            .map(|_| d.sample().unwrap().into())
            .collect::<Vec<i64>>();
        Self::new(coeffs)
    }

    #[must_use]
    #[inline]
    /// Get the len of the coefficients
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    #[must_use]
    #[inline]
    /// Return wether the polynomial is empty
    pub fn is_empty(&self) -> bool {
        self.coeffs.len() == 0
    }

    #[must_use]
    #[inline]
    /// Get the coefficients
    pub fn coeffs(&self) -> &[Coeff<P>] {
        &self.coeffs
    }

    #[must_use]
    #[inline]
    /// Compute the degree of the polynomial.
    ///
    /// This is an expensive operation, as it iterates over the coefficients.
    pub fn degree(&self) -> usize {
        let mut d = self.coeffs.len();
        while d > 0 && self.coeffs[d - 1].0 == 0 {
            d -= 1;
        }
        d
    }

    #[must_use]
    #[inline]
    /// Add two polynomials
    pub fn add(lhs: &Self, rhs: &Self) -> Self {
        let max_len = lhs.len().max(rhs.len());
        let mut coeffs = Vec::with_capacity(max_len);
        for i in 0..max_len {
            let l = lhs.coeffs().get(i).copied().unwrap_or(Coeff(0));
            let r = rhs.coeffs().get(i).copied().unwrap_or(Coeff(0));
            coeffs.push(l + r);
        }
        Self { coeffs }
    }

    #[must_use]
    #[inline]
    /// Substract two polynomials
    pub fn sub(lhs: &Self, rhs: &Self) -> Self {
        let max_len = lhs.len().max(rhs.len());
        let mut coeffs = Vec::with_capacity(max_len);
        for i in 0..max_len {
            let l = lhs.coeffs().get(i).copied().unwrap_or(Coeff(0));
            let r = rhs.coeffs().get(i).copied().unwrap_or(Coeff(0));
            coeffs.push(l - r);
        }
        Self { coeffs }
    }

    #[must_use]
    #[inline]
    /// Multiply two polynomials
    pub fn multiply(lhs: &Self, rhs: &Self) -> Self {
        let mut coeffs = alloc::vec![Coeff(0); lhs.len() + rhs.len() - 1];
        for (i, &l) in lhs.coeffs().iter().enumerate() {
            for (j, &r) in rhs.coeffs().iter().enumerate() {
                coeffs[i + j] = coeffs[i + j] + (l * r);
            }
        }
        let raw = Self { coeffs };
        raw.rem_cyclo()
    }

    #[must_use]
    /// Computes the remainder of the division by the cyclotomic polynomial X^(2^n) + 1.
    ///
    /// This is the core function of this module.
    fn rem_cyclo(self) -> Self {
        // Computing the degree is expensive.
        // As degree <= len, we simply check if len < 2^N.
        if self.len() < Self::M {
            return self;
        }

        let mut r = alloc::vec![Coeff(0); Self::M];
        // For each coefficient a_i, we "fold" according to i mod m with a sign (-1)^(i/m)
        let mut j = 0; // i % m
        let mut k = true; // if (i / m) % 2 == 0 { 1 } else { -1 }
        for &coeff in &self.coeffs {
            r[j] = if k { r[j] + coeff } else { r[j] - coeff };
            j += 1;
            if j >= Self::M {
                j = 0;
                k = !k;
            }
        }

        Self { coeffs: r }
    }
}

impl<const P: i64, const N: u32> PartialEq for Polynomial<P, N> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        let min_len = self.len().min(other.len());
        if self.coeffs[..min_len] != other.coeffs[..min_len] {
            return false;
        }
        if self.len() > min_len {
            self.coeffs[min_len..].iter().all(|&c| c.as_i64() == 0)
        } else if other.len() > min_len {
            other.coeffs[min_len..].iter().all(|&c| c.as_i64() == 0)
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coeff() {
        let c = Coeff::<7>::new(10);
        assert_eq!(c.as_i64(), 3);
    }

    #[test]
    fn test_coeff_ops() {
        let c1 = Coeff::<7>::new(10);
        let c2 = Coeff::<7>::new(5);

        assert_eq!((c1 + c2).as_i64(), 1);
        assert_eq!((c1 - c2).as_i64(), 5);
        assert_eq!((c1 * c2).as_i64(), 1);
        assert_eq!((-c1).as_i64(), 4);
    }

    #[test]
    fn test_polynomial() {
        let p1 = Polynomial::<7, 3>::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let p2 = Polynomial::<7, 3>::new(vec![8, 7, 6, 5, 4, 3, 2, 1]);

        // TODO: Other tests
    }
}
