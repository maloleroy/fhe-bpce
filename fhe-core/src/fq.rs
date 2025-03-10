//! Implementation of the F_q field (Z/qZ).
use core::ops::{Add, Mul, Sub};

#[cfg(feature = "alloc")]
pub mod polynomial;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
/// Int 64 in F_q
pub struct FqInt64<const Q: usize>(i64);

impl<const Q: usize> FqInt64<Q> {
    const Q_I64: i64 = Q as i64;

    #[must_use]
    #[inline]
    /// Constructor to create a new FqInt64
    pub const fn new(value: i64) -> Self {
        Self(value % Self::Q_I64)
    }

    #[must_use]
    #[inline]
    /// Get the value of the FqInt64
    pub const fn value(&self) -> i64 {
        self.0
    }
}

impl<const Q: usize> Add for FqInt64<Q> {
    type Output = Self;

    #[inline]
    /// Add two FqInt64
    fn add(self, rhs: Self) -> Self::Output {
        Self::new(self.0 + rhs.0)
    }
}

impl<const Q: usize> Sub for FqInt64<Q> {
    type Output = Self;

    #[inline]
    /// Subtract two FqInt64
    fn sub(self, rhs: Self) -> Self::Output {
        Self::new(self.0 - rhs.0)
    }
}

impl<const Q: usize> Mul for FqInt64<Q> {
    type Output = Self;

    #[inline]
    /// Multiply two FqInt64
    fn mul(self, rhs: Self) -> Self::Output {
        Self::new(self.0 * rhs.0)
    }
}
