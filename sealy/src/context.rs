use std::ffi::c_int;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;

use crate::EncryptionParameters;
use crate::SecurityLevel;
use crate::bindgen;
use crate::error::{Error, Result};
use crate::try_seal;

pub struct Context {
    handle: AtomicPtr<c_void>,
}

impl Context {
    /// Creates an instance of SEALContext and performs several pre-computations
    /// on the given EncryptionParameters.
    ///
    /// * `params` - The encryption parameters.
    /// * `expand_mod_chain` - Determines whether the modulus switching chain should be created.
    /// * `security_level` - Determines whether a specific security level should be enforced
    ///   according to HomomorphicEncryption.org security standard.
    pub fn new(
        params: &EncryptionParameters,
        expand_mod_chain: bool,
        security_level: SecurityLevel,
    ) -> Result<Self> {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe {
            bindgen::SEALContext_Create(
                params.get_handle(),
                expand_mod_chain,
                security_level as c_int,
                &mut handle,
            )
        })?;

        Ok(Self {
            handle: AtomicPtr::new(handle),
        })
    }

    /// Returns the handle to the underlying SEAL object.
    pub(crate) unsafe fn get_handle(&self) -> *mut c_void {
        self.handle.load(Ordering::SeqCst)
    }

    // /// Returns the security level of the encryption parameters.
    // pub fn get_security_level(&self) -> Result<SecurityLevel> {
    // 	let mut security_level: c_int = 0;

    // 	try_seal!(unsafe {
    // 		bindgen::SEALContext_GetSecurityLevel(self.get_handle(), &mut security_level)
    // 	})?;

    // 	security_level.try_into()
    // }

    /// Returns the key ContextData in the modulus switching chain.
    pub fn get_key_parms_id(&self) -> Result<Vec<u64>> {
        let mut parms_id: Vec<u64> =
            Vec::with_capacity(usize::from(EncryptionParameters::block_size()));
        try_seal!(unsafe {
            let parms_id_ptr = parms_id.as_mut_ptr();
            bindgen::SEALContext_KeyParmsId(self.get_handle(), parms_id_ptr)
        })?;
        unsafe { parms_id.set_len(4) };
        Ok(parms_id)
    }

    /// Returns the last ContextData in the modulus switching chain.
    pub fn get_last_parms_id(&self) -> Result<Vec<u64>> {
        let mut parms_id: Vec<u64> =
            Vec::with_capacity(usize::from(EncryptionParameters::block_size()));
        try_seal!(unsafe {
            let parms_id_ptr = parms_id.as_mut_ptr();
            bindgen::SEALContext_LastParmsId(self.get_handle(), parms_id_ptr)
        })?;
        unsafe { parms_id.set_len(usize::from(EncryptionParameters::block_size())) };
        Ok(parms_id)
    }

    /// Returns the first ContextData in the modulus switching chain.
    pub fn get_first_parms_id(&self) -> Result<Vec<u64>> {
        let mut parms_id: Vec<u64> =
            Vec::with_capacity(usize::from(EncryptionParameters::block_size()));
        try_seal!(unsafe {
            let parms_id_ptr = parms_id.as_mut_ptr();
            bindgen::SEALContext_FirstParmsId(self.get_handle(), parms_id_ptr)
        })?;
        unsafe { parms_id.set_len(usize::from(EncryptionParameters::block_size())) };
        Ok(parms_id)
    }

    /// Returns the encryption parameters used to create the context data.
    pub fn get_encryption_parameters(&self) -> Result<EncryptionParameters> {
        let mut parms: *mut c_void = null_mut();

        try_seal!(unsafe {
            let context_data = self.get_last_context_data()?;
            bindgen::ContextData_Parms(context_data, &mut parms)
        })?;

        Ok(EncryptionParameters { handle: parms })
    }

    /// Returns the total number of primes in the coefficient modulus.
    pub fn get_total_coeff_modulus_bit_count(&self) -> Result<i32> {
        let mut bit_count: i32 = 0;

        try_seal!(unsafe {
            let context_data = self.get_last_context_data()?;
            bindgen::ContextData_TotalCoeffModulusBitCount(context_data, &mut bit_count)
        })?;

        Ok(bit_count)
    }

    /// Returns the ContextData given a parms_id.
    #[allow(unused)]
    unsafe fn get_context_data(&self, parms_id: &[u64]) -> Result<*mut c_void> {
        let mut context_data: *mut c_void = null_mut();

        try_seal!(unsafe {
            let mut parms_id = parms_id.to_vec();
            let parms_id_ptr = parms_id.as_mut_ptr();
            bindgen::SEALContext_GetContextData(self.get_handle(), parms_id_ptr, &mut context_data)
        })?;

        if context_data.is_null() {
            return Err(Error::InvalidPointer);
        }

        Ok(context_data)
    }

    /// Returns the first ContextData in the modulus switching chain.
    #[allow(unused)]
    unsafe fn get_first_context_data(&self) -> Result<*mut c_void> {
        let mut context_data: *mut c_void = null_mut();

        try_seal!(unsafe {
            bindgen::SEALContext_FirstContextData(self.get_handle(), &mut context_data)
        })?;

        if context_data.is_null() {
            return Err(Error::InvalidPointer);
        }

        Ok(context_data)
    }

    /// Returns the last ContextData in the modulus switching chain.
    #[allow(unused)]
    unsafe fn get_last_context_data(&self) -> Result<*mut c_void> {
        let mut context_data: *mut c_void = null_mut();

        try_seal!(unsafe {
            bindgen::SEALContext_LastContextData(self.get_handle(), &mut context_data)
        })?;

        if context_data.is_null() {
            return Err(Error::InvalidPointer);
        }

        Ok(context_data)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        try_seal!(unsafe { bindgen::SEALContext_Destroy(self.get_handle()) })
            .expect("Internal error in Context::drop().");
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn can_create_and_drop_context() {
        let params = BFVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D1024)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus_u64(1234)
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();

        std::mem::drop(ctx);
    }

    #[test]
    fn test_can_get_encryption_parameters() {
        let params = BFVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D1024)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus_u64(1234)
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();
        // assert_eq!(ctx.get_security_level().unwrap(), SecurityLevel::TC128);

        let expected_params = ctx.get_encryption_parameters().unwrap();

        assert_eq!(expected_params.get_poly_modulus_degree(), 1024);
        assert_eq!(expected_params.get_scheme(), SchemeType::Bfv);
        assert_eq!(expected_params.get_plain_modulus().value(), 1234);
        assert_eq!(expected_params.get_coefficient_modulus().len(), 5);
    }
}
