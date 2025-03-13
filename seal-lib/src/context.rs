use sealy::{
    Asym, CKKSEncoder, CKKSEncryptionParametersBuilder, CKKSEvaluator, CoefficientModulusFactory,
    Context, Decryptor, Encryptor, KeyGenerator, PublicKey, SecretKey,
};
pub use sealy::{DegreeType, Evaluator, SecurityLevel};

/// A structure to build a CKKS context.
pub struct CkksContext(Context);

impl CkksContext {
    #[must_use]
    /// Create a new CKKS context.
    pub fn new(pmod: DegreeType, cmod: DegreeType, sl: SecurityLevel) -> Self {
        let params = CKKSEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(pmod)
            .set_coefficient_modulus(CoefficientModulusFactory::bfv(cmod, sl).unwrap())
            .build()
            .unwrap();

        Self(Context::new(&params, false, sl).unwrap())
    }

    #[must_use]
    #[inline]
    pub const fn context(&self) -> &Context {
        &self.0
    }

    #[must_use]
    #[inline]
    pub fn generate_keys(&self) -> (SecretKey, PublicKey) {
        let key_gen = KeyGenerator::new(self.context()).unwrap();
        (key_gen.secret_key(), key_gen.create_public_key())
    }

    #[must_use]
    #[inline]
    pub fn encoder(&self, scale: f64) -> CKKSEncoder {
        CKKSEncoder::new(self.context(), scale).unwrap()
    }

    #[must_use]
    #[inline]
    pub fn evaluator(&self) -> CKKSEvaluator {
        CKKSEvaluator::new(self.context()).unwrap()
    }

    #[must_use]
    #[inline]
    pub fn encryptor(&self, public_key: &PublicKey) -> Encryptor<Asym> {
        Encryptor::with_public_key(self.context(), public_key).unwrap()
    }

    #[must_use]
    #[inline]
    pub fn decryptor(&self, secret_key: &SecretKey) -> Decryptor {
        Decryptor::new(self.context(), secret_key).unwrap()
    }
}

impl Clone for CkksContext {
    fn clone(&self) -> Self {
        let params = self.0.get_encryption_parameters().unwrap();
        let sl = self.0.get_security_level().unwrap();
        Self(Context::new(&params, false, sl).unwrap())
    }
}
