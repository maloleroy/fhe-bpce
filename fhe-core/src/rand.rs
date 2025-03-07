//! CSRNG backed by `getrandom`
use core::mem::MaybeUninit;

pub mod distributions;

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

/// Result type for `rand` function.
pub type RandResult<T> = Result<T, getrandom::Error>;

#[cfg(test)]
mod tests {
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
