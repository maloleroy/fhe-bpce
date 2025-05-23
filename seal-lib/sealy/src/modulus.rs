use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;

use crate::bindgen;
use crate::error::{Error, Result};
use crate::try_seal;

use serde::{Deserialize, Serialize};

/// Standard security level according to the HomomorphicEncryption.org.
///
/// The value SecLevelType.None signals that no standard
/// security level should be imposed. The value SecLevelType.TC128 provides
/// a very high level of security and is the default security level enforced by
/// Microsoft SEAL when constructing a SEALContext object.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum SecurityLevel {
    /// 128-bit security level according to HomomorphicEncryption.org standard.
    TC128 = 128,
    /// 192-bit security level according to HomomorphicEncryption.org standard.
    TC192 = 192,
    /// 256-bit security level according to HomomorphicEncryption.org standard.
    TC256 = 256,
}

impl SecurityLevel {
    #[must_use]
    #[inline]
    pub const fn bits(self) -> u16 {
        match self {
            Self::TC128 => 128,
            Self::TC192 => 192,
            Self::TC256 => 256,
        }
    }
}

impl Default for SecurityLevel {
    fn default() -> Self {
        Self::TC128
    }
}

/// The available degree sizes for the polynomial modulus.
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DegreeType {
    D256,
    D512,
    D1024,
    D2048,
    D4096,
    D8192,
    D16384,
    D32768,
}

impl From<DegreeType> for u64 {
    fn from(value: DegreeType) -> Self {
        match value {
            DegreeType::D256 => 256,
            DegreeType::D512 => 512,
            DegreeType::D1024 => 1024,
            DegreeType::D2048 => 2048,
            DegreeType::D4096 => 4096,
            DegreeType::D8192 => 8192,
            DegreeType::D16384 => 16384,
            DegreeType::D32768 => 32768,
        }
    }
}

impl TryFrom<u64> for DegreeType {
    type Error = Error;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        match value {
            256 => Ok(Self::D256),
            512 => Ok(Self::D512),
            1024 => Ok(Self::D1024),
            2048 => Ok(Self::D2048),
            4096 => Ok(Self::D4096),
            8192 => Ok(Self::D8192),
            16384 => Ok(Self::D16384),
            32768 => Ok(Self::D32768),
            _ => Err(Error::DegreeNotSet),
        }
    }
}

/// Represent an integer modulus of up to 61 bits.
///
/// An instance of the Modulus
/// struct represents a non-negative integer modulus up to 61 bits. In particular,
/// the encryption parameter PlainModulus, and the primes in CoeffModulus, are
/// represented by instances of Modulus. The purpose of this class is to
/// perform and store the pre-computation required by Barrett reduction.
///
/// A Modulus is immutable from Rust once created.
pub struct Modulus {
    handle: AtomicPtr<c_void>,
}

impl Modulus {
    /// Creates a modulus from the given value.
    pub fn new(value: u64) -> Result<Self> {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe { bindgen::Modulus_Create1(value, &mut handle) })?;

        Ok(Self {
            handle: AtomicPtr::new(handle),
        })
    }

    /// Assume the given handle is a modulus and construct a modulus out of it.
    ///
    /// If it isn't, using the returned modulus results in undefined
    /// behavior.
    ///
    /// # Safety
    /// The handle must be a valid modulus handle.
    pub(crate) const unsafe fn new_unchecked_from_handle(handle: *mut c_void) -> Self {
        Self {
            handle: AtomicPtr::new(handle),
        }
    }

    /// The value of the modulus
    pub fn value(&self) -> u64 {
        let mut val: u64 = 0;

        try_seal!(unsafe { bindgen::Modulus_Value(self.get_handle(), &mut val) })
            .expect("Internal error. Could not get modulus value.");

        val
    }

    /// The handle to the internal SEAL Modulus object.
    ///
    /// # Safety
    /// This function is unsafe because it returns a raw pointer that is owned by the Modulus instance.
    /// Handling the raw pointer incorrectly can cause memory unsafety.
    pub(crate) unsafe fn get_handle(&self) -> *mut c_void {
        self.handle.load(Ordering::SeqCst)
    }
}

impl std::fmt::Debug for Modulus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", self.value())
    }
}

impl PartialEq for Modulus {
    fn eq(&self, other: &Self) -> bool {
        self.value() == other.value()
    }
}

impl Drop for Modulus {
    fn drop(&mut self) {
        try_seal!(unsafe { bindgen::Modulus_Destroy(self.get_handle()) })
            .expect("Internal error in Modulus::drop().");
    }
}

impl Clone for Modulus {
    fn clone(&self) -> Self {
        let mut copy = null_mut();

        unsafe {
            try_seal!(bindgen::Modulus_Create2(self.get_handle(), &mut copy))
                .expect("Failed to clone modulus");
        };

        Self {
            handle: AtomicPtr::new(copy),
        }
    }
}

/// This struct contains static methods for creating a coefficient modulus easily.
///
/// Note that while these functions take a SecLevelType argument, all security
/// guarantees are lost if the output is used with encryption parameters with
/// a mismatching value for the PolyModulusDegree.
///
/// The default value SecLevelType.TC128 provides a very high level of security
/// and is the default security level enforced by Microsoft SEAL when constructing
/// a SEALContext object. Normal users should not have to specify the security
/// level explicitly anywhere.
#[derive(Debug, Clone)]
pub struct CoefficientModulusFactory;

impl CoefficientModulusFactory {
    /// Returns a custom coefficient modulus suitable for use with the specified
    /// PolyModulusDegree.The return value will be a vector consisting of
    /// Modulus elements representing distinct prime numbers of bit-lengths
    /// as given in the bitSizes parameter. The bit sizes of the prime numbers
    /// can be at most 60 bits.
    pub fn build(degree: DegreeType, bit_sizes: &[i32]) -> Result<Vec<Modulus>> {
        let mut bit_sizes = bit_sizes.to_owned();
        let length = u64::try_from(bit_sizes.len()).unwrap();

        let mut coefficients: Vec<*mut c_void> = Vec::with_capacity(bit_sizes.len());
        let coefficients_ptr = coefficients.as_mut_ptr();

        try_seal!(unsafe {
            bindgen::CoeffModulus_Create1(
                degree.into(),
                length,
                bit_sizes.as_mut_ptr(),
                coefficients_ptr,
            )
        })?;

        unsafe { coefficients.set_len(usize::try_from(length).unwrap()) };

        let coeff_mod = unsafe {
            coefficients
                .into_iter()
                .map(|ptr| Modulus::new_unchecked_from_handle(ptr))
                .collect()
        };

        Ok(coeff_mod)
    }

    /// Returns a default coefficient modulus for the BFV scheme that guarantees
    /// a given security level when using a given PolyModulusDegree, according
    /// to the HomomorphicEncryption.org security standard. Note that all security
    /// guarantees are lost if the output is used with encryption parameters with
    /// a mismatching value for the PolyModulusDegree.
    ///
    /// The coefficient modulus returned by this function will not perform well
    /// if used with the CKKS scheme.
    pub fn bfv(degree: DegreeType, security_level: SecurityLevel) -> Result<Vec<Modulus>> {
        let mut len: u64 = 0;

        try_seal!(unsafe {
            bindgen::CoeffModulus_BFVDefault(
                degree.into(),
                security_level as i32,
                &mut len,
                null_mut(),
            )
        })?;

        let mut coefficients: Vec<*mut c_void> = Vec::with_capacity(usize::try_from(len).unwrap());
        let coefficients_ptr = coefficients.as_mut_ptr();

        try_seal!(unsafe {
            bindgen::CoeffModulus_BFVDefault(
                degree.into(),
                security_level as i32,
                &mut len,
                coefficients_ptr,
            )
        })?;

        unsafe { coefficients.set_len(usize::try_from(len).unwrap()) };

        let coeff_mod = unsafe {
            coefficients
                .into_iter()
                .map(|ptr| Modulus::new_unchecked_from_handle(ptr))
                .collect()
        };

        Ok(coeff_mod)
    }

    /// Returns the largest bit-length of the coefficient modulus, i.e., bit-length
    /// of the product of the primes in the coefficient modulus, that guarantees
    /// a given security level when using a given PolyModulusDegree, according
    /// to the HomomorphicEncryption.org security standard.
    #[must_use]
    pub fn max_bit_count(degree: u64, security_level: SecurityLevel) -> u32 {
        let mut bits: i32 = 0;

        unsafe { bindgen::CoeffModulus_MaxBitCount(degree, security_level as i32, &mut bits) };

        assert!(bits > 0);

        u32::try_from(bits).unwrap()
    }
}

/// Similar to [`CoefficientModulusFactory`], this struct contains static methods
/// for building [`Modulus`] instances. In this case, the modulus is used as the
/// plaintext modulus used in some FHE schemes.
pub struct PlainModulusFactory;

impl PlainModulusFactory {
    /// Creates a plain modulus with the given exact value. Batching will likely be
    /// disabled.
    pub fn raw(val: u64) -> Result<Modulus> {
        Modulus::new(val)
    }

    /// Creates a prime number Modulus for use as PlainModulus encryption
    /// parameter that supports batching with a given PolyModulusDegree.
    pub fn batching(degree: DegreeType, bit_size: u32) -> Result<Modulus> {
        let bit_sizes = vec![i32::try_from(bit_size).unwrap()];

        let modulus_chain = CoefficientModulusFactory::build(degree, bit_sizes.as_slice())?;

        Ok(modulus_chain.first().ok_or(Error::Unexpected)?.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_plain_modulus() {
        let modulus = PlainModulusFactory::batching(DegreeType::D1024, 20).unwrap();

        assert_eq!(modulus.value(), 1038337);
    }

    #[test]
    fn can_create_default_coefficient_modulus() {
        let modulus =
            CoefficientModulusFactory::bfv(DegreeType::D1024, SecurityLevel::TC128).unwrap();

        assert_eq!(modulus.len(), 1);
        assert_eq!(modulus[0].value(), 132120577);

        let modulus =
            CoefficientModulusFactory::bfv(DegreeType::D1024, SecurityLevel::TC192).unwrap();

        assert_eq!(modulus.len(), 1);
        assert_eq!(modulus[0].value(), 520193);

        let modulus =
            CoefficientModulusFactory::bfv(DegreeType::D1024, SecurityLevel::TC256).unwrap();

        assert_eq!(modulus.len(), 1);
        assert_eq!(modulus[0].value(), 12289);
    }

    #[test]
    fn can_create_custom_coefficient_modulus() {
        let modulus =
            CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap();

        assert_eq!(modulus.len(), 5);
        assert_eq!(modulus[0].value(), 1125899905744897);
        assert_eq!(modulus[1].value(), 1073643521);
        assert_eq!(modulus[2].value(), 1073692673);
        assert_eq!(modulus[3].value(), 1125899906629633);
        assert_eq!(modulus[4].value(), 1125899906826241);
    }
}
