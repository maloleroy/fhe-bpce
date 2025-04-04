use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::null_mut;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;

use crate::bindgen;
use crate::component_marker;
use crate::error::Result;
// use crate::poly_array::PolynomialArray;
use crate::try_seal;
use crate::{Asym, Ciphertext, Context, Plaintext, PublicKey, SecretKey, Sym, SymAsym};

/// Encrypts Plaintext objects into Ciphertext objects.
pub struct Encryptor<T = ()> {
    handle: AtomicPtr<c_void>,
    _marker: PhantomData<T>,
}

/// An encryptor capable of symmetric encryptions.
pub type SymmetricEncryptor = Encryptor<Sym>;

/// An encryptor capable of asymmetric encryptions.
pub type AsymmetricEncryptor = Encryptor<Asym>;

/// An encryptor capable of both symmetric and asymmetric encryptions.
pub type SymAsymEncryptor = Encryptor<SymAsym>;

impl<T> Encryptor<T> {
    /// Returns the underlying pointer to the SEAL object.
    pub(crate) unsafe fn get_handle(&self) -> *mut c_void {
        self.handle.load(Ordering::SeqCst)
    }
}

impl Encryptor {
    /// Creates an Encryptor instance initialized with the specified SEALContext,
    /// public key, and secret key.
    ///
    /// * `ctx` - The SEALContext
    /// * `publicKey` - The public key
    /// * `secretKey` - The secret key
    pub fn with_public_and_secret_key(
        ctx: &Context,
        public_key: &PublicKey,
        secret_key: &SecretKey,
    ) -> Result<Encryptor<SymAsym>> {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe {
            bindgen::Encryptor_Create(
                ctx.get_handle(),
                public_key.get_handle(),
                secret_key.get_handle(),
                &mut handle,
            )
        })?;

        Ok(Encryptor {
            handle: AtomicPtr::new(handle),
            _marker: PhantomData,
        })
    }

    /// Creates an Encryptor instance initialized with the specified SEALContext,
    /// public key.
    pub fn with_public_key(ctx: &Context, public_key: &PublicKey) -> Result<AsymmetricEncryptor> {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe {
            bindgen::Encryptor_Create(
                ctx.get_handle(),
                public_key.get_handle(),
                null_mut(),
                &mut handle,
            )
        })?;

        Ok(Encryptor {
            handle: AtomicPtr::new(handle),
            _marker: PhantomData,
        })
    }

    /// Creates an Encryptor instance initialized with the specified SEALContext and
    /// secret key.
    pub fn with_secret_key(ctx: &Context, secret_key: &SecretKey) -> Result<SymmetricEncryptor> {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe {
            bindgen::Encryptor_Create(
                ctx.get_handle(),
                null_mut(),
                secret_key.get_handle(),
                &mut handle,
            )
        })?;

        Ok(Encryptor {
            handle: AtomicPtr::new(handle),
            _marker: PhantomData,
        })
    }
}

impl AsymmetricEncryptor {
    /// Create a new asymmetric encryptor.
    pub fn new(ctx: &Context, public_key: &PublicKey) -> Result<Self> {
        Encryptor::with_public_key(ctx, public_key)
    }
}

impl SymmetricEncryptor {
    /// Create a new symmetric encryptor.
    pub fn new(ctx: &Context, secret_key: &SecretKey) -> Result<Self> {
        Encryptor::with_secret_key(ctx, secret_key)
    }
}

impl SymAsymEncryptor {
    /// Create a new encryptor capable of both symmetric and asymmetric encryption.
    pub fn new(ctx: &Context, public_key: &PublicKey, secret_key: &SecretKey) -> Result<Self> {
        Encryptor::with_public_and_secret_key(ctx, public_key, secret_key)
    }
}

impl<T: component_marker::Asym> Encryptor<T> {
    /// Encrypts a plaintext with the public key and returns the ciphertext as
    /// a serializable object.
    ///
    /// The encryption parameters for the resulting ciphertext correspond to:
    /// 1) in BFV, the highest (data) level in the modulus switching chain,
    /// 2) in CKKS, the encryption parameters of the plaintext.
    ///    Dynamic memory allocations in the process are allocated from the memory
    ///    pool pointed to by the given MemoryPoolHandle.
    ///
    /// * `plainext` - The plaintext to encrypt.
    pub fn encrypt(&self, plaintext: &Plaintext) -> Result<Ciphertext> {
        // We don't call the encrypt_return_components because the return
        // components are allocated on the SEAL global memory pool. By calling
        // the regular encrypt function, we skip that allocation.
        let ciphertext = Ciphertext::new()?;

        try_seal!(unsafe {
            bindgen::Encryptor_Encrypt(
                self.get_handle(),
                plaintext.get_handle(),
                ciphertext.get_handle(),
                null_mut(),
            )
        })?;

        Ok(ciphertext)
    }
}

impl<T: component_marker::Sym> Encryptor<T> {
    /// Encrypts a plaintext with the secret key and returns the ciphertext as
    /// a serializable object.
    ///
    /// The encryption parameters for the resulting ciphertext correspond to:
    /// 1) in BFV, the highest (data) level in the modulus switching chain,
    /// 2) in CKKS, the encryption parameters of the plaintext.
    ///    Dynamic memory allocations in the process are allocated from the memory
    ///    pool pointed to by the given MemoryPoolHandle.
    ///
    /// * `plainext` - The plaintext to encrypt.
    pub fn encrypt_symmetric(&self, plaintext: &Plaintext) -> Result<Ciphertext> {
        // We don't call the encrypt_return_components because the return
        // components are allocated on the SEAL global memory pool. By calling
        // the regular encrypt function, we skip that allocation.
        let ciphertext = Ciphertext::new()?;

        try_seal!(unsafe {
            bindgen::Encryptor_EncryptSymmetric(
                self.get_handle(),
                plaintext.get_handle(),
                false,
                ciphertext.get_handle(),
                null_mut(),
            )
        })?;

        Ok(ciphertext)
    }
}

impl<T> Drop for Encryptor<T> {
    fn drop(&mut self) {
        try_seal!(unsafe { bindgen::Encryptor_Destroy(self.get_handle()) })
            .expect("Internal error in Enryptor::drop");
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    fn mk_ctx<F>(enc_modifier: F) -> Context
    where
        F: FnOnce(BFVEncryptionParametersBuilder) -> BFVEncryptionParametersBuilder,
    {
        let builder = BFVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus_u64(1234);
        let params = enc_modifier(builder).build().unwrap();

        Context::new(&params, false, SecurityLevel::TC128).unwrap()
    }

    #[test]
    fn can_create_encryptor_from_public_key() {
        let ctx = mk_ctx(|b| b);
        let key_gen = KeyGenerator::new(&ctx).unwrap();

        let public_key = key_gen.create_public_key();

        let encryptor = Encryptor::with_public_key(&ctx, &public_key).unwrap();

        std::mem::drop(encryptor);
    }

    #[test]
    fn can_create_encryptor_from_secret_key() {
        let ctx = mk_ctx(|b| b);

        let key_gen = KeyGenerator::new(&ctx).unwrap();

        let secret_key = key_gen.secret_key();

        let encryptor = Encryptor::with_secret_key(&ctx, &secret_key).unwrap();

        std::mem::drop(encryptor);
    }

    #[test]
    fn can_create_encryptor_from_public_and_secret_key() {
        let ctx = mk_ctx(|b| b);

        let key_gen = KeyGenerator::new(&ctx).unwrap();

        let public_key = key_gen.create_public_key();
        let secret_key = key_gen.secret_key();

        let encryptor =
            Encryptor::with_public_and_secret_key(&ctx, &public_key, &secret_key).unwrap();

        std::mem::drop(encryptor);
    }
}
