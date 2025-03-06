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

/// Generate a random number in the given range using a Gaussian distribution.
///
/// # Errors
///
/// Returns an error is randomness fails to be generated.
pub fn rand_range_gaussian(_r: core::ops::Range<i64>) -> RandResult<i64> {
    todo!("Gaussian distribution")
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
}
