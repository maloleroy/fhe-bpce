use super::RandResult;
use core::ops::{Add, RangeInclusive, Sub};

pub trait Distribution {
    type Output;
    fn sample(&self) -> RandResult<Self::Output>;
}

// Trait for types that can be used as a range for random number generation.
///
/// This trait is implemented for all integer types and floating point types.
pub trait RandRange: Copy + Add + Sub + Sized {
    #[must_use]
    /// Calculates the least nonnegative remainder of self (mod rhs).
    fn rem_euclid(self, rhs: <Self as Sub>::Output) -> Self;
}

macro_rules! impl_randrange {
   ($($t:ty),*) => {
       $(impl RandRange for $t {
           #[inline]
           fn rem_euclid(self, rhs: <Self as Sub>::Output) -> Self {
               self.rem_euclid(rhs)
           }
       })*
   };
}

impl_randrange!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

impl RandRange for f32 {
    #[inline]
    fn rem_euclid(self, rhs: Self) -> Self {
        libm::remainderf(self, rhs)
        // let raw_mod = self % rhs;
        // if raw_mod < 0.0 {
        //     raw_mod + rhs
        // } else {
        //     raw_mod
        // }
    }
}

impl RandRange for f64 {
    #[inline]
    fn rem_euclid(self, rhs: Self) -> Self {
        libm::remainder(self, rhs)
        // let raw_mod = self % rhs;
        // if raw_mod < 0.0 {
        //     raw_mod + rhs
        // } else {
        //     raw_mod
        // }
    }
}

pub struct Uniform<T: RandRange> {
    range: RangeInclusive<T>,
}

impl<T: RandRange> Uniform<T> {
    #[must_use]
    #[inline]
    pub const fn new(range: RangeInclusive<T>) -> Self {
        Self { range }
    }
}

impl<T: RandRange> Distribution for Uniform<T> {
    type Output = <T as Add>::Output;
    fn sample(&self) -> RandResult<<T as Add>::Output> {
        let rd = unsafe { super::rand::<T>() }?;
        let modulus = *self.range.end() - *self.range.start();
        Ok(RandRange::rem_euclid(rd, modulus) + *self.range.start())
    }
}

/// f64 Gaussian distribution
pub struct Gaussian {
    mu: f64,
    sigma: f64,
}

impl Gaussian {
    #[must_use]
    #[inline]
    pub const fn new(mu: f64, sigma: f64) -> Self {
        Self { mu, sigma }
    }
}

impl Distribution for Gaussian {
    type Output = f64;
    fn sample(&self) -> RandResult<f64> {
        use core::f64::consts::PI;
        use libm::{cos, log, sqrt};

        let u = Uniform { range: 0.0..=1.0 };

        let u1: f64 = u.sample()?;
        let u2: f64 = u.sample()?;

        // Morph into normal distribution using Box-Muller's method
        let z0 = sqrt(-2.0 * log(u1)) * cos(2.0 * PI * u2);

        // Reshape the distribution
        Ok(self.mu + self.sigma * z0)
    }
}

pub struct Truncated<D: Distribution>
where
    D::Output: PartialOrd,
{
    d: D,
    bounds: RangeInclusive<D::Output>,
}

impl<D: Distribution> Truncated<D>
where
    D::Output: PartialOrd,
{
    #[must_use]
    #[inline]
    pub const fn new(d: D, bounds: RangeInclusive<D::Output>) -> Self {
        Self { d, bounds }
    }
}

impl<D: Distribution> Distribution for Truncated<D>
where
    D::Output: PartialOrd,
{
    type Output = D::Output;
    fn sample(&self) -> RandResult<D::Output> {
        loop {
            let rd = self.d.sample()?;
            if self.bounds.contains(&rd) {
                break Ok(rd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uniform() {
        let u = Uniform { range: 0..=10 };
        let sample = u.sample().unwrap();
        assert!(sample >= 0 && sample <= 10);
    }

    #[test]
    fn test_gaussian() {
        let g = Gaussian {
            mu: 0.0,
            sigma: 1.0,
        };
        let _sample = g.sample().unwrap();
    }

    #[test]
    fn test_truncated() {
        let g = Gaussian {
            mu: 0.0,
            sigma: 1.0,
        };
        let t = Truncated {
            d: g,
            bounds: -1.0..=1.0,
        };
        let sample = t.sample().unwrap();
        assert!(sample >= -1.0 && sample <= 1.0);
    }
}
