use std::ffi::c_void;
use std::mem::forget;
use std::os::raw::c_ulong;
use std::ptr::null_mut;

use crate::bindgen::{self};
use crate::error::Result;
use crate::error::convert_seal_error;
use crate::serialization::CompressionType;
use crate::{FromBytes, Modulus, ToBytes, try_seal};

use serde::{Deserialize, Serialize};

/// BFV encryption parameters.
mod bfv;
pub use bfv::BFVEncryptionParametersBuilder;

/// CKKS encryption parameters.
mod ckks;
pub use ckks::CKKSEncryptionParametersBuilder;

/// BGV encryption parameters.
mod bgv;
pub use bgv::BGVEncryptionParametersBuilder;

/// The FHE scheme supported by SEAL.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SchemeType {
    /// None. Don't use this.
    None = 0x0,

    /// Brakerski/Fan-Vercauteren scheme
    Bfv = 0x1,

    /// Cheon-Kim-Kim-Song scheme
    Ckks = 0x2,

    /// Brakerski-Gentry-Vaikuntanathan scheme
    Bgv = 0x3,
}

impl SchemeType {
    /// Converts a u8 to a SchemeType.
    #[must_use]
    pub fn from_u8(val: u8) -> Self {
        match val {
            0x0 => Self::None,
            0x1 => Self::Bfv,
            0x2 => Self::Ckks,
            0x3 => Self::Bgv,
            _ => panic!("Illegal scheme type"),
        }
    }

    /// Converts a SchemeType to a u8.
    #[must_use]
    pub const fn to_u8(&self) -> u8 {
        *self as u8
    }
}

/// An immutable collection of parameters that defines an encryption scheme.
/// Use either the `CKKSBuilder` or `BFVBuilder` to create one of these. Once created,
/// these objects are effectively immutable.
#[derive(Debug)]
pub struct EncryptionParameters {
    pub(crate) handle: *mut c_void,
}

unsafe impl Sync for EncryptionParameters {}
unsafe impl Send for EncryptionParameters {}

impl EncryptionParameters {
    /// Creates a new `EncryptionParameters` instance given a scheme type.
    pub fn new(scheme: SchemeType) -> Result<Self> {
        let mut handle: *mut c_void = null_mut();

        convert_seal_error(unsafe { bindgen::EncParams_Create1(scheme as u8, &mut handle) })?;

        Ok(Self { handle })
    }

    /// The block size is always 4 for SEAL. That means every
    /// parms_id is a 4-tuple of 64-bit integers. representing the
    /// hash of the encryption parameters.
    #[must_use]
    pub const fn block_size() -> u8 {
        4
    }

    /// Returns the handle to the underlying SEAL object.
    #[must_use]
    pub const fn get_handle(&self) -> *mut c_void {
        self.handle
    }

    /// Returns the polynomial degree of the underlying CKKS or BFV scheme.
    #[must_use]
    pub fn get_poly_modulus_degree(&self) -> u64 {
        let mut degree: u64 = 0;

        unsafe {
            convert_seal_error(bindgen::EncParams_GetPolyModulusDegree(
                self.handle,
                &mut degree,
            ))
            .expect("Internal error");
        };

        degree
    }

    /// Get the underlying scheme.
    #[must_use]
    pub fn get_scheme(&self) -> SchemeType {
        let mut scheme: u8 = 0;

        unsafe {
            convert_seal_error(bindgen::EncParams_GetScheme(self.handle, &mut scheme))
                .expect("Internal error");
        };

        SchemeType::from_u8(scheme)
    }

    /// Returns the plain text modulus for the encryption scheme.
    #[must_use]
    pub fn get_plain_modulus(&self) -> Modulus {
        let mut borrowed_modulus = null_mut();

        unsafe {
            convert_seal_error(bindgen::EncParams_GetPlainModulus(
                self.handle,
                &mut borrowed_modulus,
            ))
            .expect("Internal error");
        };

        let borrowed_modulus = unsafe { Modulus::new_unchecked_from_handle(borrowed_modulus) };

        // We don't own the modulus we were given, so copy one we do own
        // and don't drop the old one.
        let ret = borrowed_modulus.clone();
        forget(borrowed_modulus);

        ret
    }

    /// Returns the coefficient modulus for the encryption scheme.
    #[must_use]
    pub fn get_coefficient_modulus(&self) -> Vec<Modulus> {
        let mut len: u64 = 0;

        unsafe {
            convert_seal_error(bindgen::EncParams_GetCoeffModulus(
                self.handle,
                &mut len,
                null_mut(),
            ))
            .expect("Internal error");
        };

        let mut borrowed_modulus = Vec::with_capacity(usize::try_from(len).unwrap());
        let borrowed_modulus_ptr = borrowed_modulus.as_mut_ptr();

        unsafe {
            convert_seal_error(bindgen::EncParams_GetCoeffModulus(
                self.handle,
                &mut len,
                borrowed_modulus_ptr,
            ))
            .expect("Internal error");

            borrowed_modulus.set_len(usize::try_from(len).unwrap());
        };

        borrowed_modulus
            .iter()
            .map(|h| {
                let modulus = unsafe { Modulus::new_unchecked_from_handle(*h) };
                let ret = modulus.clone();

                forget(modulus);

                ret
            })
            .collect()
    }

    /// Returns the parms id.
    #[must_use]
    pub fn get_parms_id(&self) -> u64 {
        let mut parms_id: c_ulong = 0;

        unsafe {
            convert_seal_error(bindgen::EncParams_GetParmsId(self.handle, &mut parms_id))
                .expect("Internal error");
        }

        parms_id
    }

    /// Sets the polynomial modulus degree.
    pub fn set_coefficient_modulus(&mut self, modulus: &[Modulus]) -> Result<()> {
        unsafe {
            let modulus_ref = modulus
                .iter()
                .map(|m| m.get_handle())
                .collect::<Vec<*mut c_void>>();

            let modulus_ptr = modulus_ref.as_ptr().cast_mut();

            try_seal!(bindgen::EncParams_SetCoeffModulus(
                self.handle,
                modulus.len() as u64,
                modulus_ptr
            ))
        }
    }

    /// Sets the polynomial modulus degree.
    pub fn set_poly_modulus_degree(&mut self, degree: u64) -> Result<()> {
        convert_seal_error(unsafe { bindgen::EncParams_SetPolyModulusDegree(self.handle, degree) })
    }

    /// Sets the plain modulus as a [`Modulus`] instance.
    pub fn set_plain_modulus(&mut self, modulus: &Modulus) -> Result<()> {
        convert_seal_error(unsafe {
            bindgen::EncParams_SetPlainModulus1(self.handle, modulus.get_handle())
        })
    }

    /// Sets the plain modulus as a constant.
    pub fn set_plain_modulus_u64(&mut self, modulus: u64) -> Result<()> {
        convert_seal_error(unsafe { bindgen::EncParams_SetPlainModulus2(self.handle, modulus) })
    }
}

/// The coefficient modulus is a list of distinct [`Modulus`] instances.
#[derive(Debug, PartialEq)]
pub enum CoefficientModulusType {
    /// The coefficient modulus is not set.
    NotSet,
    /// The coefficient modulus is defined as a list of distinct [`Modulus`] instances.
    Modulus(Vec<Modulus>),
}

/// The plain modulus is either a constant or a [`Modulus`] instance.
#[derive(Debug, PartialEq)]
pub enum PlainModulusType {
    /// The plain modulus is not set.
    NotSet,
    /// The plain modulus is defined as a constant.
    Constant(u64),
    /// The plain modulus is defined as a [`Modulus`] instance.
    Modulus(Modulus),
}

impl Drop for EncryptionParameters {
    fn drop(&mut self) {
        convert_seal_error(unsafe { bindgen::EncParams_Destroy(self.handle) })
            .expect("Internal error in EncryptionParameters::drop().");
    }
}

impl ToBytes for EncryptionParameters {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut num_bytes: i64 = 0;

        convert_seal_error(unsafe {
            bindgen::EncParams_SaveSize(self.handle, CompressionType::ZStd as u8, &mut num_bytes)
        })?;

        let mut data: Vec<u8> = Vec::with_capacity(usize::try_from(num_bytes).unwrap());
        let mut bytes_written: i64 = 0;

        convert_seal_error(unsafe {
            let data_ptr = data.as_mut_ptr();

            bindgen::EncParams_Save(
                self.handle,
                data_ptr,
                u64::try_from(num_bytes).unwrap(),
                CompressionType::ZStd as u8,
                &mut bytes_written,
            )
        })?;

        unsafe { data.set_len(usize::try_from(bytes_written).unwrap()) };

        Ok(data)
    }
}

impl FromBytes for EncryptionParameters {
    type State = SchemeType;
    fn from_bytes(scheme: &SchemeType, bytes: &[u8]) -> Result<Self> {
        let key = Self::new(*scheme)?;
        let mut bytes_read = 0;

        convert_seal_error(unsafe {
            bindgen::EncParams_Load(
                key.handle,
                bytes.as_ptr().cast_mut(),
                u64::try_from(bytes.len()).unwrap(),
                &mut bytes_read,
            )
        })?;

        Ok(key)
    }
}
