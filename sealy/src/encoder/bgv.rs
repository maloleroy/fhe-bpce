use std::ffi::c_void;
use std::fmt::Debug;
use std::ptr::null_mut;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;

use crate::bindgen;
use crate::error::Result;
use crate::try_seal;
use crate::{Context, Plaintext};

pub struct BGVEncoder {
    handle: AtomicPtr<c_void>,
}

impl BGVEncoder {
    /// Creates a BatchEncoder. It is necessary that the encryption parameters
    /// given through the SEALContext object support batching. This means you
    /// used PlainModulus::batching when you created your encryption_parameters.
    ///
    /// * `ctx` - The Context
    pub fn new(ctx: &Context) -> Result<Self> {
        let mut handle: *mut c_void = null_mut();

        try_seal!(unsafe { bindgen::BatchEncoder_Create(ctx.get_handle(), &mut handle) })?;

        Ok(Self {
            handle: AtomicPtr::new(handle),
        })
    }

    /// Get the handle to the underlying SEAL object.
    pub(crate) unsafe fn get_handle(&self) -> *mut c_void {
        self.handle.load(Ordering::SeqCst)
    }

    /// Returns the number of "Batched" slots in this encoder produces.
    pub fn get_slot_count(&self) -> usize {
        let mut count: u64 = 0;

        try_seal!(unsafe { bindgen::BatchEncoder_GetSlotCount(self.get_handle(), &mut count) })
            .expect("Internal error in BVTEncoder::get_slot_count().");

        usize::try_from(count).unwrap()
    }

    /// Creates a plaintext from a given matrix. This function "batches" a given matrix
    /// of integers modulo the plaintext modulus into a plaintext element, and stores
    /// the result in the destination parameter. The input vector must have size at most equal
    /// to the degree of the polynomial modulus. The first half of the elements represent the
    /// first row of the matrix, and the second half represent the second row. The numbers
    /// in the matrix can be at most equal to the plaintext modulus for it to represent
    /// a valid plaintext.
    ///
    /// The matrix's elements are of type `u64`.
    ///
    ///  * `data` - The `2xN` matrix of integers modulo plaintext modulus to batch
    pub fn encode_u64(&self, data: &[u64]) -> Result<Plaintext> {
        let plaintext = Plaintext::new()?;

        // I pinky promise SEAL won't mutate data, the C bindings just aren't
        // const correct.
        try_seal!(unsafe {
            bindgen::BatchEncoder_Encode1(
                self.get_handle(),
                u64::try_from(data.len()).unwrap(),
                data.as_ptr().cast_mut(),
                plaintext.get_handle(),
            )
        })?;

        Ok(plaintext)
    }

    /// Inverse of encode. This function "unbatches" a given plaintext into a matrix
    /// of integers modulo the plaintext modulus, and stores the result in the destination
    /// parameter. The input plaintext must have degrees less than the polynomial modulus,
    /// and coefficients less than the plaintext modulus, i.e. it must be a valid plaintext
    /// for the encryption parameters. Dynamic memory allocations in the process are
    /// allocated from the memory pool pointed to by the given MemoryPoolHandle.
    ///
    /// The input plaintext matrix should be known to contain `u64` elements.
    ///
    ///   * `plain` - The plaintext polynomial to unbatch
    pub fn decode_u64(&self, plaintext: &Plaintext) -> Result<Vec<u64>> {
        let mut data = Vec::with_capacity(self.get_slot_count());
        let data_ptr = data.as_mut_ptr();
        let mut size: u64 = 0;

        try_seal!(unsafe {
            bindgen::BatchEncoder_Decode1(
                self.get_handle(),
                plaintext.get_handle(),
                &mut size,
                data_ptr,
                null_mut(),
            )
        })?;

        assert!(
            (data.capacity() >= usize::try_from(size).unwrap()),
            "Allocation overflow BVTEncoder::decode_unsigned"
        );

        unsafe {
            data.set_len(usize::try_from(size).unwrap());
        }

        Ok(data)
    }

    /// Creates a plaintext from a given matrix. This function "batches" a given matrix
    /// of integers modulo the plaintext modulus into a plaintext element, and stores
    /// the result in the destination parameter. The input vector must have size at most equal
    /// to the degree of the polynomial modulus. The first half of the elements represent the
    /// first row of the matrix, and the second half represent the second row. The numbers
    /// in the matrix can be at most equal to the plaintext modulus for it to represent
    /// a valid plaintext.
    ///
    /// The matrix's elements are of type `i64`.
    ///
    ///  * `data` - The `2xN` matrix of integers modulo plaintext modulus to batch
    pub fn encode_i64(&self, data: &[i64]) -> Result<Plaintext> {
        let plaintext = Plaintext::new()?;

        // We pinky promise SEAL won't mutate data, the C bindings just aren't
        // const correct.
        try_seal!(unsafe {
            bindgen::BatchEncoder_Encode2(
                self.get_handle(),
                u64::try_from(data.len()).unwrap(),
                data.as_ptr().cast_mut(),
                plaintext.get_handle(),
            )
        })?;

        Ok(plaintext)
    }

    /// Inverse of encode. This function "unbatches" a given plaintext into a matrix
    /// of integers modulo the plaintext modulus, and stores the result in the destination
    /// parameter. The input plaintext must have degrees less than the polynomial modulus,
    /// and coefficients less than the plaintext modulus, i.e. it must be a valid plaintext
    /// for the encryption parameters. Dynamic memory allocations in the process are
    /// allocated from the memory pool pointed to by the given MemoryPoolHandle.
    ///
    /// The input plaintext matrix should be known to contain `i64` elements.
    ///
    ///  * `plain` - The plaintext polynomial to unbatch
    pub fn decode_i64(&self, plaintext: &Plaintext) -> Result<Vec<i64>> {
        let mut data = Vec::with_capacity(self.get_slot_count());
        let data_ptr = data.as_mut_ptr();
        let mut size: u64 = 0;

        try_seal!(unsafe {
            bindgen::BatchEncoder_Decode2(
                self.get_handle(),
                plaintext.get_handle(),
                &mut size,
                data_ptr,
                null_mut(),
            )
        })?;

        assert!(
            (data.capacity() >= usize::try_from(size).unwrap()),
            "Allocation overflow BVTEncoder::decode_unsigned"
        );

        unsafe {
            data.set_len(usize::try_from(size).unwrap());
        }

        Ok(data)
    }

    /// Encodes a slice of float point numbers as integers.
    ///
    /// * `values` - The slice of float point numbers to encode.
    pub fn encode_f64(&self, data: &[f64], base: f64) -> Result<Plaintext> {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let unsigned_data: Vec<u64> = data.iter().map(|v| (v * base).round() as u64).collect();

        self.encode_u64(&unsigned_data)
    }

    /// Decodes a slice of integers to float point numbers.
    ///
    /// * `values` - The slice of integers to decode.
    pub fn decode_f64(&self, plaintext: &Plaintext, base: f64) -> Result<Vec<f64>> {
        let unsigned_data: Vec<u64> = self.decode_u64(plaintext)?;

        #[allow(clippy::cast_precision_loss)]
        Ok(unsigned_data.iter().map(|v| *v as f64 / base).collect())
    }
}

impl Drop for BGVEncoder {
    fn drop(&mut self) {
        try_seal!(unsafe { bindgen::BatchEncoder_Destroy(self.get_handle()) })
            .expect("Internal error in BGVEncoder::drop.");
    }
}

impl Debug for BGVEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BGVEncoder")
            .field("handle", &self.handle)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn can_create_and_drop_bgv_encoder() {
        let params = BGVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus(PlainModulusFactory::batching(DegreeType::D8192, 20).unwrap())
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();

        let encoder = BGVEncoder::new(&ctx).unwrap();

        std::mem::drop(encoder);
    }

    #[test]
    fn can_get_slots_bgv_encoder() {
        let params = BGVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus(PlainModulusFactory::batching(DegreeType::D8192, 20).unwrap())
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();

        let encoder = BGVEncoder::new(&ctx).unwrap();

        assert_eq!(encoder.get_slot_count(), 8192);
    }

    #[test]
    fn can_get_encode_and_decode_unsigned() {
        let params = BGVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus(PlainModulusFactory::batching(DegreeType::D8192, 20).unwrap())
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();

        let encoder = BGVEncoder::new(&ctx).unwrap();

        let mut data = Vec::with_capacity(8192);

        for i in 0..encoder.get_slot_count() {
            data.push(u64::try_from(i).unwrap());
        }

        let plaintext = encoder.encode_u64(&data).unwrap();
        let data_2 = encoder.decode_u64(&plaintext).unwrap();

        assert_eq!(data, data_2);
    }

    #[test]
    fn can_get_encode_and_decode_signed() {
        let params = BGVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus(PlainModulusFactory::batching(DegreeType::D8192, 20).unwrap())
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();

        let encoder = BGVEncoder::new(&ctx).unwrap();

        let mut data = Vec::with_capacity(8192);

        for i in 0..encoder.get_slot_count() {
            data.push(i64::try_from(i).unwrap());
        }

        let plaintext = encoder.encode_i64(&data).unwrap();
        let data_2 = encoder.decode_i64(&plaintext).unwrap();

        assert_eq!(data, data_2);
    }

    #[test]
    fn scalar_encoder_can_encode_decode_signed() {
        let params = BGVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus(PlainModulusFactory::batching(DegreeType::D8192, 20).unwrap())
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();

        let encoder = BGVEncoder::new(&ctx).unwrap();

        let encoded = encoder.encode_i64(&[-15i64]).unwrap();
        let decoded = encoder.decode_i64(&encoded).unwrap();

        assert_eq!(decoded[0], -15);
    }

    #[test]
    fn scalar_encoder_can_encode_decode_unsigned() {
        let params = BGVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus(PlainModulusFactory::batching(DegreeType::D8192, 20).unwrap())
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();

        let encoder = BGVEncoder::new(&ctx).unwrap();

        let encoded = encoder.encode_i64(&[42i64]).unwrap();
        let decoded = encoder.decode_i64(&encoded).unwrap();

        assert_eq!(decoded[0], 42);
    }

    #[test]
    #[ignore = "Not working yet because of integer size limitation of BGV"]
    fn can_get_encode_and_decode_float() {
        let params = BGVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus(PlainModulusFactory::batching(DegreeType::D8192, 20).unwrap())
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();

        let base = 2.0f64.powi(40);
        let encoder = BGVEncoder::new(&ctx).unwrap();

        let encoded = encoder.encode_f64(&[42f64], base).unwrap();
        let decoded = encoder.decode_f64(&encoded, base).unwrap();

        assert!((decoded[0] - 42f64).abs() < 1e-10);
    }
}
