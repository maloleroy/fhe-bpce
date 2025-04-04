use std::ffi::c_void;
use std::fmt::Debug;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::{Context, FromBytes, ToBytes, bindgen, serialization::CompressionType};
use crate::{error::Result, try_seal};

/// Class to store a ciphertext element.
pub struct Ciphertext {
    handle: AtomicPtr<c_void>,
}

impl Ciphertext {
    /// Creates a new empty plaintext. Use an encoder to populate with a value.
    pub fn new() -> Result<Self> {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe { bindgen::Ciphertext_Create1(null_mut(), &mut handle) })?;

        Ok(Self {
            handle: AtomicPtr::new(handle),
        })
    }

    /// Returns the handle to the underlying SEAL object.
    pub(crate) unsafe fn get_handle(&self) -> *mut c_void {
        self.handle.load(Ordering::SeqCst)
    }

    /// Returns the number of polynomials in this ciphertext.
    pub fn num_polynomials(&self) -> u64 {
        let mut size: u64 = 0;

        try_seal!(unsafe { bindgen::Ciphertext_Size(self.get_handle(), &mut size) }).unwrap();

        size
    }

    /// Returns the number of components in the coefficient modulus.
    pub fn coeff_modulus_size(&self) -> u64 {
        let mut size: u64 = 0;

        try_seal!(unsafe { bindgen::Ciphertext_CoeffModulusSize(self.get_handle(), &mut size) })
            .unwrap();

        size
    }

    /// Returns the value at a specific point in the coefficient array. This is
    /// not publically exported as it leaks the encoding of the array.
    #[allow(dead_code)]
    pub(crate) fn get_data(&self, index: usize) -> Result<u64> {
        let mut value: u64 = 0;

        try_seal!(unsafe {
            bindgen::Ciphertext_GetDataAt1(
                self.get_handle(),
                u64::try_from(index).unwrap(),
                &mut value,
            )
        })?;

        Ok(value)
    }

    /// Returns the coefficient in the form the ciphertext is currently in (NTT
    /// form or not). For BFV, this will be the coefficient in the residual
    /// number system (RNS) format.
    pub fn get_coefficient(&self, poly_index: usize, coeff_index: usize) -> Result<Vec<u64>> {
        let size = self.coeff_modulus_size();
        let mut data: Vec<u64> = Vec::with_capacity(usize::try_from(size).unwrap());

        try_seal!(unsafe {
            let data_ptr = data.as_mut_ptr();

            bindgen::Ciphertext_GetDataAt2(
                self.get_handle(),
                u64::try_from(poly_index).unwrap(),
                u64::try_from(coeff_index).unwrap(),
                data_ptr,
            )
        })?;

        unsafe { data.set_len(usize::try_from(size).unwrap()) };

        Ok(data.clone())
    }

    /// Returns whether the ciphertext is in NTT form.
    pub fn is_ntt_form(&self) -> bool {
        let mut result = false;

        try_seal!(unsafe { bindgen::Ciphertext_IsNTTForm(self.get_handle(), &mut result) })
            .expect("Fatal error in Plaintext::is_ntt_form().");

        result
    }
}

impl Debug for Ciphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ciphertext")
            .field("handle", &self.handle)
            .finish()
    }
}

impl Clone for Ciphertext {
    fn clone(&self) -> Self {
        let mut handle = null_mut();

        try_seal!(unsafe { bindgen::Ciphertext_Create2(self.get_handle(), &mut handle) })
            .expect("Fatal error: Failed to clone ciphertext");

        Self {
            handle: AtomicPtr::new(handle),
        }
    }
}

impl AsRef<Self> for Ciphertext {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl ToBytes for Ciphertext {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut num_bytes: i64 = 0;

        try_seal!(unsafe {
            bindgen::Ciphertext_SaveSize(
                self.get_handle(),
                CompressionType::ZStd as u8,
                &mut num_bytes,
            )
        })?;

        let mut data: Vec<u8> = Vec::with_capacity(usize::try_from(num_bytes).unwrap());
        let mut bytes_written: i64 = 0;

        try_seal!(unsafe {
            let data_ptr = data.as_mut_ptr();

            bindgen::Ciphertext_Save(
                self.get_handle(),
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

impl FromBytes for Ciphertext {
    type State = Context;
    fn from_bytes(context: &Context, bytes: &[u8]) -> Result<Self> {
        let ciphertext = Self::new()?;
        let mut bytes_read = 0_i64;

        try_seal!(unsafe {
            bindgen::Ciphertext_Load(
                ciphertext.get_handle(),
                context.get_handle(),
                bytes.as_ptr().cast_mut(),
                u64::try_from(bytes.len()).unwrap(),
                &mut bytes_read,
            )
        })?;

        Ok(ciphertext)
    }
}

impl Drop for Ciphertext {
    fn drop(&mut self) {
        try_seal!(unsafe { bindgen::Ciphertext_Destroy(self.get_handle()) })
            .expect("Internal error in Ciphertext::drop");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_and_destroy_ciphertext() {
        let ciphertext = Ciphertext::new().unwrap();

        std::mem::drop(ciphertext);
    }
}
