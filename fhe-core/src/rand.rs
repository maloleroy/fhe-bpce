//! CSRNG backed by `getrandom`
use core::{
    mem::MaybeUninit,
    ops::{Add, Sub},
};

/// Generate a random value of type `T` using `getrandom`.
///
/// # Safety
///
/// Any arbitrary sequence of bytes (of len `size_of::<T>()`) is a valid instance of type `T`.
///
/// # Errors
///
/// Returns an error is randomness fails to be generated.
pub unsafe fn rand<T: Sized>() -> RandResult<T> {
    let mut value = MaybeUninit::<T>::uninit();

    // Safety:
    // `MaybeUninit<T>` is guaranteed to have the same memory layout as `T`.
    // Thus we can safely interpret the memory as a slice of bytes.
    let rd_slice =
        unsafe { core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), size_of::<T>()) };
    getrandom::fill(rd_slice)?;

    // Safety:
    // Function safety guards ensure that `value` is properly initialized.
    Ok(unsafe { value.assume_init() })
}

/// Randomly fills the given slice with random bytes using `getrandom`.
///
/// # Errors
///
/// Returns an error is randomness fails to be generated.
pub fn rand_slice<T: Sized>(slice: &mut [MaybeUninit<T>]) -> RandResult<()> {
    // Safety:
    // Thanks to `size_of_val`, we can safely interpret the memory as a slice of bytes.
    let rd_slice = unsafe {
        core::slice::from_raw_parts_mut(slice.as_mut_ptr().cast::<u8>(), size_of_val(slice))
    };
    getrandom::fill(rd_slice)?;

    Ok(())
}

/// Trait for types that can be used as a range for random number generation.
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

/// Generate a random instance of type `T` in the given range.
///
/// # Errors
///
/// Returns an error is randomness fails to be generated.
pub fn rand_range<T: RandRange>(r: core::ops::Range<T>) -> RandResult<<T as Add>::Output> {
    let rd = unsafe { rand::<T>() }?;
    let modulus = r.end - r.start;
    Ok(RandRange::rem_euclid(rd, modulus) + r.start)
}

/// Generate a random number using a Gaussian distribution.
///
/// # Errors
///
/// Returns an error is randomness fails to be generated.
pub fn rand_gaussian(mu: f64, sigma: f64) -> RandResult<f64> {
    use core::f64::consts::PI;
    use libm::{cos, log, sqrt};

    let u1: f64 = rand_range(0.0..1.0)?;
    let u2: f64 = rand_range(0.0..1.0)?;

    // Morph into normal distribution using Box-Muller's method
    let z0 = sqrt(-2.0 * log(u1)) * cos(2.0 * PI * u2);

    // Reshape the distribution
    Ok(mu + sigma * z0)
}

/// Generate a random bounded number using a Gaussian distribution.
///
/// Note that because this is a truncated distribution, it contains a loop that may run for a long time.
///
/// # Errors
///
/// Returns an error is randomness fails to be generated.
pub fn rand_gaussian_truncated(mu: f64, sigma: f64, beta: f64) -> RandResult<f64> {
    loop {
        let gaussian = rand_gaussian(mu, sigma)?;

        if gaussian >= mu - beta && gaussian <= mu + beta {
            break Ok(gaussian);
        }
    }
}

/// Result type for `rand` function.
pub type RandResult<T> = Result<T, getrandom::Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand_range() {
        macro_rules! test_rand_range {
            ($t:ty, $range:expr, $nb:expr) => {{
                for _ in 0..$nb {
                    let rd = rand_range($range).unwrap();
                    assert!($range.contains(&rd));
                }
            }};
        }

        test_rand_range!(u8, 3..42, 15);
        test_rand_range!(u32, 3..42, 20);
        test_rand_range!(i64, -178..99999, 20);
    }

    #[cfg(miri)]
    #[test]
    fn test_rand_slice() {
        let mut slice = [MaybeUninit::<u32>::uninit(); 10];
        rand_slice(&mut slice).unwrap();
    }

    #[cfg(miri)]
    #[test]
    fn test_rand() {
        #[repr(C)]
        struct Weird {
            a: u64,
            b: u32,
            c: f32,
        }

        unsafe { rand::<Weird>() }.unwrap();
    }

    #[test]
    fn test_gaussian_truncated() {
        let mu = 0.0;
        let sigma = 1.0;
        let beta = 1.0;

        for _ in 0..10 {
            let gaussian = rand_gaussian_truncated(mu, sigma, beta).unwrap();
            assert!((mu - beta) <= gaussian && gaussian <= (mu + beta));
        }
    }
}
