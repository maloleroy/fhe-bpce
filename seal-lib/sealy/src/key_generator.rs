use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;

use crate::bindgen;
use crate::error::Result;
use crate::serialization::CompressionType;
use crate::try_seal;
use crate::{Context, FromBytes, ToBytes};

use serde::ser::Error;
use serde::{Serialize, Serializer};

/// Generates matching secret key and public key.
///
/// An existing KeyGenerator can also at any time be used to
/// generate relinearization keys and Galois keys.
/// Constructing a KeyGenerator requires only a SEALContext.
#[derive(Debug)]
pub struct KeyGenerator {
    handle: AtomicPtr<c_void>,
}

impl KeyGenerator {
    /// Creates a KeyGenerator initialized with the specified SEALContext.
    /// Dynamically allocated member variables are allocated from the global memory pool.
    ///
    /// * `context` - The context describing the encryption scheme.
    pub fn new(ctx: &Context) -> Result<Self> {
        let mut handle = null_mut();

        try_seal!(unsafe { bindgen::KeyGenerator_Create1(ctx.get_handle(), &mut handle) })?;

        Ok(Self {
            handle: AtomicPtr::new(handle),
        })
    }

    /// Creates an KeyGenerator instance initialized with the specified
    /// SEALContext and specified previously secret key. This can e.g. be used
    /// to increase the number of relinearization keys from what had earlier
    /// been generated, or to generate Galois keys in case they had not been
    /// generated earlier.
    ///
    /// * `context` - The context describing the encryption scheme.
    /// * `secret_key` - A previously generated secret key
    pub fn new_from_secret_key(ctx: &Context, secret_key: &SecretKey) -> Result<Self> {
        let mut handle = null_mut();

        try_seal!(unsafe {
            bindgen::KeyGenerator_Create2(ctx.get_handle(), secret_key.handle, &mut handle)
        })?;

        Ok(Self {
            handle: AtomicPtr::new(handle),
        })
    }

    /// Returns a copy of the secret key.
    pub fn secret_key(&self) -> SecretKey {
        let mut handle = null_mut();

        try_seal!(unsafe { bindgen::KeyGenerator_SecretKey(self.get_handle(), &mut handle) })
            .expect("Fatal error in KeyGenerator::secret_key");

        SecretKey { handle }
    }

    /// Returns the handle to the underlying SEAL object.
    pub(crate) unsafe fn get_handle(&self) -> *mut c_void {
        self.handle.load(Ordering::SeqCst)
    }

    /// Generates and returns a new public key.
    pub fn create_public_key(&self) -> PublicKey {
        self.create_public_key_internal(false)
    }

    /// Generates and returns a compact public key.
    ///
    ///  Half of the key data is pseudo-randomly generated from a seed to reduce
    ///  the object size. The resulting serializable object cannot be used
    ///  directly and is meant to be serialized for the size reduction to have an
    ///  impact.
    pub fn create_compact_public_key(&self) -> CompactPublicKey {
        CompactPublicKey(self.create_public_key_internal(true))
    }

    fn create_public_key_internal(&self, save_seed: bool) -> PublicKey {
        let mut handle = null_mut();

        try_seal!(unsafe {
            bindgen::KeyGenerator_CreatePublicKey(self.get_handle(), save_seed, &mut handle)
        })
        .expect("Fatal error in KeyGenerator::public_key");

        PublicKey { handle }
    }

    /// Creates relinearization keys
    pub fn create_relinearization_keys(&self) -> Result<RelinearizationKey> {
        self.create_relinearization_keys_internal(false)
    }

    /// Generates and returns relinearization keys as a serializable object.
    /// Every time this function is called, new relinearization keys will be
    /// generated.
    ///
    /// Half of the key data is pseudo-randomly generated from a seed to reduce
    /// the object size. The resulting serializable object cannot be used
    /// directly and is meant to be serialized for the size reduction to have an
    /// impact.
    pub fn create_compact_relinearization_keys(&self) -> Result<CompactRelinearizationKey> {
        Ok(CompactRelinearizationKey(
            self.create_relinearization_keys_internal(true)?,
        ))
    }

    fn create_relinearization_keys_internal(&self, save_seed: bool) -> Result<RelinearizationKey> {
        let mut handle = null_mut();

        try_seal!(unsafe {
            bindgen::KeyGenerator_CreateRelinKeys(self.get_handle(), save_seed, &mut handle)
        })?;

        Ok(RelinearizationKey { handle })
    }

    /// Generates and returns Galois keys as a serializable object.
    ///
    /// Generates and returns Galois keys as a serializable object. Every time
    /// this function is called, new Galois keys will be generated.
    ///
    /// Half of the key data is pseudo-randomly generated from a seed to reduce
    /// the object size. The resulting serializable object cannot be used
    /// directly and is meant to be serialized for the size reduction to have an
    /// impact.
    ///
    /// This function creates logarithmically many (in degree of the polynomial
    /// modulus) Galois keys that is sufficient to apply any Galois automorphism
    /// (e.g. rotations) on encrypted data. Most users will want to use this
    /// overload of the function.
    pub fn create_compact_galois_keys(&self) -> Result<CompactGaloisKeys> {
        Ok(CompactGaloisKeys(self.create_galois_keys_internal(true)?))
    }

    /// Generates Galois keys and stores the result in destination.
    ///
    /// # Remarks
    /// Generates Galois keys and stores the result in destination. Every time
    /// this function is called, new Galois keys will be generated.
    ///
    /// This function creates logarithmically many (in degree of the polynomial
    /// modulus) Galois keys that is sufficient to apply any Galois automorphism
    /// (e.g. rotations) on encrypted data. Most users will want to use this
    /// overload of the function.
    pub fn create_galois_keys(&self) -> Result<GaloisKey> {
        self.create_galois_keys_internal(false)
    }

    fn create_galois_keys_internal(&self, save_seed: bool) -> Result<GaloisKey> {
        let mut handle = null_mut();

        try_seal!(unsafe {
            bindgen::KeyGenerator_CreateGaloisKeysAll(self.get_handle(), save_seed, &mut handle)
        })?;

        Ok(GaloisKey { handle })
    }
}

impl Drop for KeyGenerator {
    fn drop(&mut self) {
        try_seal!(unsafe { bindgen::KeyGenerator_Destroy(self.get_handle()) })
            .expect("Fatal error in KeyGenerator::drop");
    }
}

/// Class to store a public key.
#[derive(Debug)]
pub struct PublicKey {
    handle: *mut c_void,
}

unsafe impl Sync for PublicKey {}
unsafe impl Send for PublicKey {}

impl ToBytes for PublicKey {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut num_bytes: i64 = 0;

        try_seal!(unsafe {
            bindgen::PublicKey_SaveSize(self.handle, CompressionType::ZStd as u8, &mut num_bytes)
        })?;

        let mut data: Vec<u8> = Vec::with_capacity(usize::try_from(num_bytes).unwrap());
        let mut bytes_written: i64 = 0;

        try_seal!(unsafe {
            let data_ptr = data.as_mut_ptr();

            bindgen::PublicKey_Save(
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

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl FromBytes for PublicKey {
    type State = Context;
    fn from_bytes(context: &Context, bytes: &[u8]) -> Result<Self> {
        let key = Self::new()?;
        let mut bytes_read = 0;

        try_seal!(unsafe {
            bindgen::PublicKey_Load(
                key.handle,
                context.get_handle(),
                bytes.as_ptr().cast_mut(),
                u64::try_from(bytes.len()).unwrap(),
                &mut bytes_read,
            )
        })?;

        Ok(key)
    }
}

impl PublicKey {
    /// Creates a new PublicKey.
    pub fn new() -> Result<Self> {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe { bindgen::PublicKey_Create1(&mut handle) })?;

        Ok(Self { handle })
    }

    /// Returns the handle to the underlying SEAL object.
    #[must_use]
    pub const fn get_handle(&self) -> *mut c_void {
        self.handle
    }
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        try_seal!(unsafe { bindgen::PublicKey_Destroy(self.handle) })
            .expect("Fatal error in PublicKey::drop");
    }
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe { bindgen::PublicKey_Create2(self.handle, &mut handle) })
            .expect("Fatal error in PublicKey::clone");

        Self { handle }
    }
}

impl AsRef<Self> for PublicKey {
    fn as_ref(&self) -> &Self {
        self
    }
}

/// A public key that stores a random number seed to generate the rest of the key.
/// This form isn't directly usable, but serializes in a very compact representation.
pub struct CompactPublicKey(PublicKey);

impl CompactPublicKey {
    /// Returns the key as a byte array.
    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        self.0.as_bytes()
    }
}

/// Class to store a secret key.
pub struct SecretKey {
    handle: *mut c_void,
}

unsafe impl Sync for SecretKey {}
unsafe impl Send for SecretKey {}

impl SecretKey {
    /// Creates a new SecretKey.
    pub fn new() -> Result<Self> {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe { bindgen::SecretKey_Create1(&mut handle) })?;

        Ok(Self { handle })
    }

    /// Returns the handle to the underlying SEAL object.
    #[must_use]
    pub const fn get_handle(&self) -> *mut c_void {
        self.handle
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl ToBytes for SecretKey {
    /// Returns the key as a byte array.
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut num_bytes: i64 = 0;

        try_seal!(unsafe {
            bindgen::SecretKey_SaveSize(self.handle, CompressionType::ZStd as u8, &mut num_bytes)
        })?;

        let mut data: Vec<u8> = Vec::with_capacity(usize::try_from(num_bytes).unwrap());
        let mut bytes_written: i64 = 0;

        try_seal!(unsafe {
            let data_ptr = data.as_mut_ptr();

            bindgen::SecretKey_Save(
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

impl FromBytes for SecretKey {
    type State = Context;
    fn from_bytes(context: &Context, bytes: &[u8]) -> Result<Self> {
        let key = Self::new()?;
        let mut bytes_read = 0;

        try_seal!(unsafe {
            bindgen::SecretKey_Load(
                key.handle,
                context.get_handle(),
                bytes.as_ptr().cast_mut(),
                u64::try_from(bytes.len()).unwrap(),
                &mut bytes_read,
            )
        })?;

        Ok(key)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        try_seal!(unsafe { bindgen::SecretKey_Destroy(self.handle) })
            .expect("Fatal error in SecretKey::drop");
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = self
            .as_bytes()
            .map_err(|e| S::Error::custom(format!("Failed to get secret key bytes: {e}")))?;

        serializer.serialize_bytes(&data)
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe { bindgen::SecretKey_Create2(self.handle, &mut handle) })
            .expect("Fatal error in SecretKey::clone");

        Self { handle }
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("SecretKey")
            .field("handle", &"<ELIDED>")
            .finish()
    }
}

impl AsRef<Self> for SecretKey {
    fn as_ref(&self) -> &Self {
        self
    }
}

/// Class to store relinearization keys.
///
/// Freshly encrypted ciphertexts have a size of 2, and multiplying ciphertexts
/// of sizes K and L results in a ciphertext of size K+L-1. Unfortunately, this
/// growth in size slows down further multiplications and increases noise growth.
/// Relinearization is an operation that has no semantic meaning, but it reduces
/// the size of ciphertexts back to 2. Microsoft SEAL can only relinearize size 3
/// ciphertexts back to size 2, so if the ciphertexts grow larger than size 3,
/// there is no way to reduce their size. Relinearization requires an instance of
/// RelinKeys to be created by the secret key owner and to be shared with the
/// evaluator. Note that plain multiplication is fundamentally different from
/// normal multiplication and does not result in ciphertext size growth.
///
/// Typically, one should always relinearize after each multiplications. However,
/// in some cases relinearization should be postponed as late as possible due to
/// its computational cost.For example, suppose the computation involves several
/// homomorphic multiplications followed by a sum of the results. In this case it
/// makes sense to not relinearize each product, but instead add them first and
/// only then relinearize the sum. This is particularly important when using the
/// CKKS scheme, where relinearization is much more computationally costly than
/// multiplications and additions.
#[derive(Debug)]
pub struct RelinearizationKey {
    handle: *mut c_void,
}

unsafe impl Sync for RelinearizationKey {}
unsafe impl Send for RelinearizationKey {}

impl RelinearizationKey {
    /// Returns the handle to the underlying SEAL object.
    #[must_use]
    pub const fn get_handle(&self) -> *mut c_void {
        self.handle
    }

    /// Creates a new RelinearizationKeys.
    pub fn new() -> Result<Self> {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe { bindgen::KSwitchKeys_Create1(&mut handle) })?;

        Ok(Self { handle })
    }

    /// Returns the key as a byte array.
    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut num_bytes: i64 = 0;

        try_seal!(unsafe {
            bindgen::KSwitchKeys_SaveSize(self.handle, CompressionType::ZStd as u8, &mut num_bytes)
        })?;

        let mut data: Vec<u8> = Vec::with_capacity(usize::try_from(num_bytes).unwrap());
        let mut bytes_written: i64 = 0;

        try_seal!(unsafe {
            let data_ptr = data.as_mut_ptr();

            bindgen::KSwitchKeys_Save(
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

impl PartialEq for RelinearizationKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl ToBytes for RelinearizationKey {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut num_bytes: i64 = 0;

        try_seal!(unsafe {
            bindgen::KSwitchKeys_SaveSize(self.handle, CompressionType::ZStd as u8, &mut num_bytes)
        })?;

        let mut data: Vec<u8> = Vec::with_capacity(usize::try_from(num_bytes).unwrap());
        let mut bytes_written: i64 = 0;

        try_seal!(unsafe {
            let data_ptr = data.as_mut_ptr();

            bindgen::KSwitchKeys_Save(
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

impl FromBytes for RelinearizationKey {
    type State = Context;
    fn from_bytes(context: &Context, bytes: &[u8]) -> Result<Self> {
        let keys = Self::new()?;
        let mut write_bytes: i64 = 0;

        try_seal!(unsafe {
            bindgen::KSwitchKeys_Load(
                keys.handle,
                context.get_handle(),
                bytes.as_ptr().cast_mut(),
                u64::try_from(bytes.len()).unwrap(),
                &mut write_bytes,
            )
        })?;

        Ok(keys)
    }
}

impl Drop for RelinearizationKey {
    fn drop(&mut self) {
        try_seal!(unsafe {
            // RelinKeys doesn't have a destructor, but inherits
            // from KSwitchKeys, which does. Just call the base class's
            // destructor.
            bindgen::KSwitchKeys_Destroy(self.handle)
        })
        .expect("Fatal error in PublicKey::drop()");
    }
}

impl Clone for RelinearizationKey {
    fn clone(&self) -> Self {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe {
            // RelinearizationKeys don't have any data members, so we simply call the parent
            // class's copy constructor.
            bindgen::KSwitchKeys_Create2(self.handle, &mut handle)
        })
        .expect("Failed to clone Galois keys.");

        Self { handle }
    }
}

#[derive(PartialEq)]
/// A relinearization key that stores a random number seed to generate the rest of the key.
/// This form isn't directly usable, but serializes in a compact representation.
pub struct CompactRelinearizationKey(RelinearizationKey);

impl CompactRelinearizationKey {
    /// Returns the key as a byte array.
    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        self.0.as_bytes()
    }
}

/// Class to store Galois keys.
///
/// Slot rotations
/// Galois keys are certain types of public keys that are needed to perform encrypted
/// vector rotation operations on batched ciphertexts. Batched ciphertexts encrypt
/// a 2-by-(N/2) matrix of modular integers in the BFV scheme, or an N/2-dimensional
/// vector of complex numbers in the CKKS scheme, where N denotes the degree of the
/// polynomial modulus. In the BFV scheme Galois keys can enable both cyclic rotations
/// of the encrypted matrix rows, as well as row swaps (column rotations). In the CKKS
/// scheme Galois keys can enable cyclic vector rotations, as well as a complex
/// conjugation operation.
#[derive(Debug)]
pub struct GaloisKey {
    handle: *mut c_void,
}

unsafe impl Sync for GaloisKey {}
unsafe impl Send for GaloisKey {}

impl GaloisKey {
    /// Returns the handle to the underlying SEAL object.
    #[must_use]
    pub const fn get_handle(&self) -> *mut c_void {
        self.handle
    }

    /// Creates a new GaloisKey.
    pub fn new() -> Result<Self> {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe { bindgen::KSwitchKeys_Create1(&mut handle) })?;

        Ok(Self { handle })
    }
}

impl PartialEq for GaloisKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl ToBytes for GaloisKey {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut num_bytes: i64 = 0;

        try_seal!(unsafe {
            bindgen::KSwitchKeys_SaveSize(self.handle, CompressionType::ZStd as u8, &mut num_bytes)
        })?;

        let mut data: Vec<u8> = Vec::with_capacity(usize::try_from(num_bytes).unwrap());
        let mut bytes_written: i64 = 0;

        try_seal!(unsafe {
            let data_ptr = data.as_mut_ptr();

            bindgen::KSwitchKeys_Save(
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

impl FromBytes for GaloisKey {
    type State = Context;
    fn from_bytes(context: &Context, bytes: &[u8]) -> Result<Self> {
        let keys = Self::new()?;
        let mut write_bytes: i64 = 0;

        try_seal!(unsafe {
            bindgen::KSwitchKeys_Load(
                keys.handle,
                context.get_handle(),
                bytes.as_ptr().cast_mut(),
                u64::try_from(bytes.len()).unwrap(),
                &mut write_bytes,
            )
        })?;

        Ok(keys)
    }
}

impl Drop for GaloisKey {
    fn drop(&mut self) {
        try_seal!(unsafe {
            // GaloisKeys doesn't have a destructor, but inherits
            // from KSwitchKeys, which does. Just call the base class's
            // destructor.
            bindgen::KSwitchKeys_Destroy(self.handle)
        })
        .expect("Fatal error in GaloisKeys::drop()");
    }
}

impl Clone for GaloisKey {
    fn clone(&self) -> Self {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe {
            // GaloisKeys don't have any data members, so we simply call the parent
            // class's copy constructor.
            bindgen::KSwitchKeys_Create2(self.handle, &mut handle)
        })
        .expect("Failed to clone Galois keys.");

        Self { handle }
    }
}

#[derive(PartialEq)]
/// A galois key set that stores a random number seed to generate the rest of the key.
/// This form isn't directly usable, but serializes in a compact representation.
pub struct CompactGaloisKeys(GaloisKey);

impl CompactGaloisKeys {
    /// Returns the key as a byte array.
    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn can_create_secret_key() {
        let params = BFVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus_u64(1234)
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();
        let key_gen = KeyGenerator::new(&ctx).unwrap();

        let _secret_key = key_gen.secret_key();
    }

    #[test]
    fn can_create_public_key() {
        let params = BFVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus_u64(1234)
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();
        let key_gen = KeyGenerator::new(&ctx).unwrap();

        key_gen.create_public_key();
    }

    #[test]
    fn can_create_relin_key() {
        let params = BFVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus_u64(1234)
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();
        let key_gen = KeyGenerator::new(&ctx).unwrap();

        key_gen.create_relinearization_keys().unwrap();
    }

    #[test]
    fn can_create_galois_key() {
        let params = BFVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::bfv(DegreeType::D8192, SecurityLevel::TC128).unwrap(),
            )
            .set_plain_modulus(PlainModulusFactory::batching(DegreeType::D8192, 32).unwrap())
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();
        let key_gen = KeyGenerator::new(&ctx).unwrap();

        key_gen.create_galois_keys().unwrap();
    }

    #[test]
    fn can_init_from_existing_secret_key() {
        let params = BFVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus_u64(1234)
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();
        let key_gen = KeyGenerator::new(&ctx).unwrap();

        let _secret_key = key_gen.secret_key();
    }
}
