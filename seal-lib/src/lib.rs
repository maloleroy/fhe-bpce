//! Convenient wrapper around Microsoft SEAL library.
#![no_std]

extern crate alloc;
use alloc::vec::Vec;

pub use bincode::{Decode, Encode};
use fhe_core::api::CryptoSystem;
pub use sealy::{
    BFVEncoder, BFVEvaluator, CKKSEncoder, CKKSEvaluator, Decryptor, DegreeType, Evaluator,
    Plaintext, PublicKey, SecretKey, SecurityLevel,
};
use sealy::{FromBytes as _, ToBytes as _};

pub mod context;
mod impls;

#[derive(Clone)]
/// Ciphertext from Microsoft SEAL.
pub struct Ciphertext(pub sealy::Ciphertext);

impl Encode for Ciphertext {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.0.as_bytes().unwrap().encode(encoder)
    }
}

impl Decode<context::SealCkksContext> for Ciphertext {
    fn decode<D: bincode::de::Decoder<Context = context::SealCkksContext>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let raw: Vec<_> = Decode::decode(decoder)?;
        Ok(Self(
            sealy::Ciphertext::from_bytes(decoder.context().context(), &raw).unwrap(),
        ))
    }
}
impl Decode<context::SealBFVContext> for Ciphertext {
    fn decode<D: bincode::de::Decoder<Context = context::SealBFVContext>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let raw: Vec<_> = Decode::decode(decoder)?;
        Ok(Self(
            sealy::Ciphertext::from_bytes(decoder.context().context(), &raw).unwrap(),
        ))
    }
}

/// The CKKS CryptoSystem backed by Microsoft SEAL.
pub struct SealCkksCS {
    encoder: sealy::CKKSEncoder,
    evaluator: sealy::CKKSEvaluator,
    encryptor: sealy::Encryptor<sealy::Asym>,
    decryptor: sealy::Decryptor,
    relin_key: sealy::RelinearizationKey,
}

impl SealCkksCS {
    pub fn new(context: context::SealCkksContext, scale: f64) -> Self {
        let (skey, pkey, relin_key) = context.generate_keys();

        let encoder = context.encoder(scale);
        let evaluator = context.evaluator();
        let encryptor = context.encryptor(&pkey);
        let decryptor = context.decryptor(&skey);

        Self {
            encoder,
            evaluator,
            encryptor,
            decryptor,
            relin_key,
        }
    }
}

impl CryptoSystem for SealCkksCS {
    type Ciphertext = Ciphertext;
    type Plaintext = f64;
    type Operation = CkksHOperation;

    fn cipher(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        let encoded = self.encoder.encode_f64(&[*plaintext]).unwrap();
        Ciphertext(self.encryptor.encrypt(&encoded).unwrap())
    }

    fn decipher(&self, ciphertext: &Self::Ciphertext) -> Self::Plaintext {
        let decrypted = self.decryptor.decrypt(&ciphertext.0).unwrap();
        self.encoder.decode_f64(&decrypted).unwrap()[0]
    }

    fn operate(
        &self,
        operation: Self::Operation,
        lhs: &Self::Ciphertext,
        rhs: Option<&Self::Ciphertext>,
    ) -> Self::Ciphertext {
        match operation {
            CkksHOperation::Add => {
                let rhs = rhs.expect("Addition requires two operands.");
                let result = impls::homom_add(&self.evaluator, &lhs.0, &rhs.0);
                Ciphertext(result)
            }
            CkksHOperation::Mul => {
                let rhs = rhs.expect("Multiplication requires two operands.");
                let result = impls::homom_mul(&self.evaluator, &lhs.0, &rhs.0);
                Ciphertext(result)
            }
            CkksHOperation::Exp(pow) => {
                debug_assert!(rhs.is_none());
                let result = impls::homom_exp(&self.evaluator, &lhs.0, pow, &self.relin_key);
                Ciphertext(result)
            }
        }
    }

    fn relinearize(&self, ciphertext: &mut Self::Ciphertext) {
        *ciphertext = Ciphertext(impls::relinearize(
            &self.evaluator,
            &mut ciphertext.0,
            &self.relin_key,
        ));
    }
}

#[derive(Clone, Copy, Debug, Encode, Decode)]
#[non_exhaustive]
pub enum CkksHOperation {
    Add,
    Mul,
    Exp(u64),
}

pub struct SealBfvCS {
    encoder: sealy::BFVEncoder,
    evaluator: sealy::BFVEvaluator,
    encryptor: sealy::Encryptor<sealy::Asym>,
    decryptor: sealy::Decryptor,
}

impl SealBfvCS {
    pub fn new(context: context::SealBFVContext) -> Self {
        let (skey, pkey) = context.generate_keys();

        let encoder = context.encoder();
        let evaluator = context.evaluator();
        let encryptor = context.encryptor(&pkey);
        let decryptor = context.decryptor(&skey);

        Self {
            encoder,
            evaluator,
            encryptor,
            decryptor,
        }
    }
}

impl CryptoSystem for SealBfvCS {
    type Ciphertext = Ciphertext;
    type Plaintext = u64;
    type Operation = BfvHOperation;

    fn cipher(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        let encoded = self.encoder.encode_u64(&[*plaintext]).unwrap();
        Ciphertext(self.encryptor.encrypt(&encoded).unwrap())
    }

    fn decipher(&self, ciphertext: &Self::Ciphertext) -> Self::Plaintext {
        let decrypted = self.decryptor.decrypt(&ciphertext.0).unwrap();
        self.encoder.decode_u64(&decrypted).unwrap()[0]
    }

    fn operate(
        &self,
        operation: Self::Operation,
        lhs: &Self::Ciphertext,
        rhs: Option<&Self::Ciphertext>,
    ) -> Self::Ciphertext {
        match operation {
            BfvHOperation::Add => {
                let rhs = rhs.expect("Addition requires two operands.");
                let result = impls::homom_add(&self.evaluator, &lhs.0, &rhs.0);
                Ciphertext(result)
            }
            BfvHOperation::Mul => {
                let rhs = rhs.expect("Multiplication requires two operands.");
                let result = impls::homom_mul(&self.evaluator, &lhs.0, &rhs.0);
                Ciphertext(result)
            }
        }
    }

    fn relinearize(&self, _ciphertext: &mut Self::Ciphertext) {
        // No relinearization in BFV
    }
}

#[derive(Clone, Copy, Debug, Encode, Decode)]
#[non_exhaustive]
pub enum BfvHOperation {
    Add,
    Mul,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{SealBFVContext, SealCkksContext};
    use fhe_core::{api::CryptoSystem, f64::approx_eq};

    const PRECISION: f64 = 5e-2;

    #[test]
    fn test_seal_ckks_cs() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);

        let a = cs.cipher(&1.0);
        let b = cs.cipher(&2.0);
        let c = cs.operate(CkksHOperation::Add, &a, Some(&b));
        let d = cs.operate(CkksHOperation::Mul, &a, Some(&b));

        let a = cs.decipher(&a);
        let b = cs.decipher(&b);
        let c = cs.decipher(&c);
        let d = cs.decipher(&d);

        assert!(approx_eq(a, 1.0, PRECISION));
        assert!(approx_eq(b, 2.0, PRECISION));
        assert!(approx_eq(c, 3.0, PRECISION));
        assert!(approx_eq(d, 2.0, PRECISION));
    }

    #[test]
    fn test_seal_ckks_cs_exp() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);

        let a = cs.cipher(&2.0);
        let e = cs.operate(CkksHOperation::Exp(3), &a, None);

        let d = cs.decipher(&e);

        assert!(approx_eq(d, 8.0, PRECISION));
    }

    #[test]
    fn test_seal_ckks_cs_linear_sum() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);

        let a_plaintext = 1.0;
        let a_coeff_plaintext = 2.0;
        let b_plaintext = 3.0;
        let b_coeff_plaintext = 4.0;

        let a = cs.cipher(&a_plaintext);
        let a_coeff = cs.cipher(&a_coeff_plaintext);
        let b = cs.cipher(&b_plaintext);
        let b_coeff = cs.cipher(&b_coeff_plaintext);
        let ac = cs.operate(CkksHOperation::Mul, &a, Some(&a_coeff));
        let bc = cs.operate(CkksHOperation::Mul, &b, Some(&b_coeff));
        let sum = cs.operate(CkksHOperation::Add, &ac, Some(&bc));

        let decrypted_sum = cs.decipher(&sum);
        let expected_sum = a_plaintext * a_coeff_plaintext + b_plaintext * b_coeff_plaintext;

        assert!(approx_eq(decrypted_sum, expected_sum, 5e-2))
    }

    #[test]
    fn test_seal_bfv_cs() {
        let context = SealBFVContext::new(DegreeType::D2048, SecurityLevel::TC128, 16);
        let cs = SealBfvCS::new(context);

        let a_plaintext = 1;
        let b_plaintext = 2;

        let a = cs.cipher(&a_plaintext);
        let b = cs.cipher(&b_plaintext);
        let c = cs.operate(BfvHOperation::Add, &a, Some(&b));
        let d = cs.operate(BfvHOperation::Mul, &a, Some(&b));

        let a = cs.decipher(&a);
        let b = cs.decipher(&b);
        let c = cs.decipher(&c);
        let d = cs.decipher(&d);

        assert_eq!(a, a_plaintext);
        assert_eq!(b, b_plaintext);
        assert_eq!(c, a_plaintext + b_plaintext);
        assert_eq!(d, a_plaintext * b_plaintext);
    }
}
