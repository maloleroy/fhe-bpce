use sealy::{
    Asym, BFVEncoder, BFVEncryptionParametersBuilder, BFVEvaluator, CKKSEncoder,
    CKKSEncryptionParametersBuilder, CKKSEvaluator, CoefficientModulusFactory, Context, Decryptor,
    Encryptor, KeyGenerator, PlainModulusFactory, PublicKey, RelinearizationKey, SecretKey,
};
pub use sealy::{DegreeType, Evaluator, SecurityLevel};

/// A context for CKKS operations.
pub struct SealCkksContext(Context);

impl SealCkksContext {
    #[must_use]
    /// Create a new CKKS context.
    pub fn new(degree: DegreeType, sl: SecurityLevel) -> Self {
        let params = CKKSEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(degree)
            .set_coefficient_modulus(CoefficientModulusFactory::bfv(degree, sl).unwrap())
            .build()
            .unwrap();

        Self(Context::new(&params, false, sl).unwrap())
    }

    #[must_use]
    #[inline]
    pub(super) const fn context(&self) -> &Context {
        &self.0
    }

    #[must_use]
    #[inline]
    /// Generate a set of secret, public and relinearization keys.
    pub fn generate_keys(&self) -> (SecretKey, PublicKey, Option<RelinearizationKey>) {
        let key_gen = KeyGenerator::new(self.context()).unwrap();

        let sk = key_gen.secret_key();
        let pk = key_gen.create_public_key();
        let rk = key_gen.create_relinearization_keys().ok();

        (sk, pk, rk)
    }

    #[must_use]
    #[inline]
    /// Create a new encoder.
    pub fn encoder(&self, scale: f64) -> CKKSEncoder {
        CKKSEncoder::new(self.context(), scale).unwrap()
    }

    #[must_use]
    #[inline]
    /// Create a new evaluator.
    pub fn evaluator(&self) -> CKKSEvaluator {
        CKKSEvaluator::new(self.context()).unwrap()
    }

    #[must_use]
    #[inline]
    /// Create a new encryptor.
    pub fn encryptor(&self, public_key: &PublicKey) -> Encryptor<Asym> {
        Encryptor::with_public_key(self.context(), public_key).unwrap()
    }

    #[must_use]
    #[inline]
    /// Create a new decryptor.
    pub fn decryptor(&self, secret_key: &SecretKey) -> Decryptor {
        Decryptor::new(self.context(), secret_key).unwrap()
    }
}

impl Clone for SealCkksContext {
    fn clone(&self) -> Self {
        let params = self.0.get_encryption_parameters().unwrap();
        let sl = self.0.get_security_level().unwrap();
        Self(Context::new(&params, false, sl).unwrap())
    }
}

/// A structure to build a BFV context.
pub struct SealBFVContext(Context);

impl SealBFVContext {
    #[must_use]
    /// Create a new BFV context.
    pub fn new(degree: DegreeType, sl: SecurityLevel, bit_size: u32) -> Self {
        let params = BFVEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(degree)
            .set_plain_modulus(PlainModulusFactory::batching(degree, bit_size).unwrap())
            .set_coefficient_modulus(CoefficientModulusFactory::bfv(degree, sl).unwrap())
            .build()
            .unwrap();

        Self(Context::new(&params, false, sl).unwrap())
    }

    #[must_use]
    #[inline]
    pub(super) const fn context(&self) -> &Context {
        &self.0
    }

    #[must_use]
    #[inline]
    /// Generate a pair of secret and public keys.
    pub fn generate_keys(&self) -> (SecretKey, PublicKey, Option<RelinearizationKey>) {
        let key_gen = KeyGenerator::new(self.context()).unwrap();

        let sk = key_gen.secret_key();
        let pk = key_gen.create_public_key();
        let rk = key_gen.create_relinearization_keys().ok();

        (sk, pk, rk)
    }

    #[must_use]
    #[inline]
    /// Create a new encoder.
    pub fn encoder(&self) -> BFVEncoder {
        BFVEncoder::new(self.context()).unwrap()
    }

    #[must_use]
    #[inline]
    /// Create a new evaluator.
    pub fn evaluator(&self) -> BFVEvaluator {
        BFVEvaluator::new(self.context()).unwrap()
    }

    #[must_use]
    #[inline]
    /// Create a new encryptor.
    pub fn encryptor(&self, public_key: &PublicKey) -> Encryptor<Asym> {
        Encryptor::with_public_key(self.context(), public_key).unwrap()
    }

    #[must_use]
    #[inline]
    /// Create a new decryptor.
    pub fn decryptor(&self, secret_key: &SecretKey) -> Decryptor {
        Decryptor::new(self.context(), secret_key).unwrap()
    }
}

impl Clone for SealBFVContext {
    fn clone(&self) -> Self {
        let params = self.0.get_encryption_parameters().unwrap();
        let sl = self.0.get_security_level().unwrap();
        Self(Context::new(&params, false, sl).unwrap())
    }
}
