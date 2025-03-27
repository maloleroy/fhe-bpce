//! Convenient wrapper around Microsoft SEAL library.
#![no_std]
#![forbid(unsafe_code)]
#![warn(clippy::nursery, clippy::pedantic)]
#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

extern crate alloc;
use alloc::vec::Vec;

pub use bincode::{Decode, Encode};
use fhe_core::api::{Arity1Operation, Arity2Operation, CryptoSystem, Operation};
use fhe_operations::selectable_collection::{Flag, SelectableCS};
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
    relin_key: Option<sealy::RelinearizationKey>,
}

impl SealCkksCS {
    pub fn new(context: &context::SealCkksContext, scale: f64) -> Self {
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
    type Operation1 = CkksHOperation1;
    type Operation2 = CkksHOperation2;

    fn cipher(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        let encoded = self.encoder.encode_f64(&[*plaintext]).unwrap();
        Ciphertext(self.encryptor.encrypt(&encoded).unwrap())
    }

    fn decipher(&self, ciphertext: &Self::Ciphertext) -> Self::Plaintext {
        let decrypted = self.decryptor.decrypt(&ciphertext.0).unwrap();
        self.encoder.decode_f64(&decrypted).unwrap()[0]
    }

    fn operate1(&self, operation: Self::Operation1, lhs: &Self::Ciphertext) -> Self::Ciphertext {
        match operation {
            CkksHOperation1::AddPlain(plain) => {
                let plain_encoded = self.encoder.encode_f64(&[plain]).unwrap();
                let result = impls::homom_add_plain(&self.evaluator, &lhs.0, &plain_encoded);
                Ciphertext(result)
            }
            CkksHOperation1::MulPlain(plain) => {
                let plain_encoded = self.encoder.encode_f64(&[plain]).unwrap();
                let result = impls::homom_mul_plain(&self.evaluator, &lhs.0, &plain_encoded);
                Ciphertext(result)
            }
            CkksHOperation1::Resize => panic!("Resize operation needs operate_mut, not operate."),
        }
    }

    fn operate2(
        &self,
        operation: Self::Operation2,
        lhs: &Self::Ciphertext,
        rhs: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        match operation {
            CkksHOperation2::Add => {
                let result = impls::homom_add(&self.evaluator, &lhs.0, &rhs.0);
                Ciphertext(result)
            }
            CkksHOperation2::Mul => {
                let result = impls::homom_mul(&self.evaluator, &lhs.0, &rhs.0);
                Ciphertext(result)
            }
        }
    }

    fn operate1_inplace(&self, operation: Self::Operation1, lhs: &mut Self::Ciphertext) {
        match operation {
            CkksHOperation1::Resize => impls::resize(&self.evaluator, &mut lhs.0),
            CkksHOperation1::AddPlain(plain) => {
                let plain_encoded = self.encoder.encode_f64(&[plain]).unwrap();
                impls::homom_add_plain_inplace(&self.evaluator, &mut lhs.0, &plain_encoded);
            }
            CkksHOperation1::MulPlain(plain) => {
                let plain_encoded = self.encoder.encode_f64(&[plain]).unwrap();
                impls::homom_mul_plain_inplace(&self.evaluator, &mut lhs.0, &plain_encoded);
            }
        }
    }

    fn operate2_inplace(
        &self,
        operation: Self::Operation2,
        lhs: &mut Self::Ciphertext,
        rhs: &Self::Ciphertext,
    ) {
        match operation {
            CkksHOperation2::Add => {
                impls::homom_add_inplace(&self.evaluator, &mut lhs.0, &rhs.0);
            }
            CkksHOperation2::Mul => {
                impls::homom_mul_inplace(&self.evaluator, &mut lhs.0, &rhs.0);
            }
        }
    }

    fn relinearize(&self, ciphertext: &mut Self::Ciphertext) {
        *ciphertext = Ciphertext(impls::relinearize(
            &self.evaluator,
            &ciphertext.0,
            self.relin_key.as_ref().unwrap(),
        ));
    }
}

impl SelectableCS for SealCkksCS {
    const ADD_OPP: Self::Operation2 = CkksHOperation2::Add;
    const MUL_OPP: Self::Operation2 = CkksHOperation2::Mul;

    fn flag_to_plaintext(&self, flag: Flag) -> Self::Plaintext {
        const FLAG_ON: f64 = 1.0;
        const FLAG_OFF: f64 = 0.0;

        match flag {
            Flag::On => FLAG_ON,
            Flag::Off => FLAG_OFF,
        }
    }
}

#[derive(Clone, Copy, Debug, Encode, Decode)]
#[non_exhaustive]
pub enum CkksHOperation1 {
    AddPlain(f64),
    MulPlain(f64),
    Resize,
}
impl Operation for CkksHOperation1 {}
impl Arity1Operation for CkksHOperation1 {}

#[derive(Clone, Copy, Debug, Encode, Decode)]
#[non_exhaustive]
pub enum CkksHOperation2 {
    Add,
    Mul,
}
impl Operation for CkksHOperation2 {}
impl Arity2Operation for CkksHOperation2 {}

pub struct SealBfvCS {
    encoder: sealy::BFVEncoder,
    evaluator: sealy::BFVEvaluator,
    encryptor: sealy::Encryptor<sealy::Asym>,
    decryptor: sealy::Decryptor,
    relin_key: Option<sealy::RelinearizationKey>,
}

impl SealBfvCS {
    pub fn new(context: &context::SealBFVContext) -> Self {
        let (skey, pkey, relin_key) = context.generate_keys();

        let encoder = context.encoder();
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

impl CryptoSystem for SealBfvCS {
    type Ciphertext = Ciphertext;
    type Plaintext = u64;
    type Operation1 = BfvHOperation1;
    type Operation2 = BfvHOperation2;

    fn cipher(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        let encoded = self.encoder.encode_u64(&[*plaintext]).unwrap();
        Ciphertext(self.encryptor.encrypt(&encoded).unwrap())
    }

    fn decipher(&self, ciphertext: &Self::Ciphertext) -> Self::Plaintext {
        let decrypted = self.decryptor.decrypt(&ciphertext.0).unwrap();
        self.encoder.decode_u64(&decrypted).unwrap()[0]
    }

    fn operate1(&self, operation: Self::Operation1, lhs: &Self::Ciphertext) -> Self::Ciphertext {
        match operation {
            BfvHOperation1::AddPlain(plain) => {
                let plain_encoded = self.encoder.encode_u64(&[plain]).unwrap();
                let result = impls::homom_add_plain(&self.evaluator, &lhs.0, &plain_encoded);
                Ciphertext(result)
            }
            BfvHOperation1::MulPlain(plain) => {
                let plain_encoded = self.encoder.encode_u64(&[plain]).unwrap();
                let result = impls::homom_mul_plain(&self.evaluator, &lhs.0, &plain_encoded);
                Ciphertext(result)
            }
            BfvHOperation1::Exp(exp) => {
                let result = impls::homom_exp(
                    &self.evaluator,
                    &lhs.0,
                    exp,
                    self.relin_key.as_ref().unwrap(),
                );
                Ciphertext(result)
            }
        }
    }

    fn operate2(
        &self,
        operation: Self::Operation2,
        lhs: &Self::Ciphertext,
        rhs: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        match operation {
            BfvHOperation2::Add => {
                let result = impls::homom_add(&self.evaluator, &lhs.0, &rhs.0);
                Ciphertext(result)
            }
            BfvHOperation2::Mul => {
                let result = impls::homom_mul(&self.evaluator, &lhs.0, &rhs.0);
                Ciphertext(result)
            }
        }
    }

    fn operate1_inplace(&self, operation: Self::Operation1, lhs: &mut Self::Ciphertext) {
        match operation {
            BfvHOperation1::AddPlain(plain) => {
                let plain_encoded = self.encoder.encode_u64(&[plain]).unwrap();
                impls::homom_add_plain_inplace(&self.evaluator, &mut lhs.0, &plain_encoded);
            }
            BfvHOperation1::MulPlain(plain) => {
                let plain_encoded = self.encoder.encode_u64(&[plain]).unwrap();
                impls::homom_mul_plain_inplace(&self.evaluator, &mut lhs.0, &plain_encoded);
            }
            BfvHOperation1::Exp(exp) => {
                *lhs = Ciphertext(impls::homom_exp(
                    &self.evaluator,
                    &lhs.0,
                    exp,
                    self.relin_key.as_ref().unwrap(),
                ));
            }
        }
    }

    fn operate2_inplace(
        &self,
        operation: Self::Operation2,
        lhs: &mut Self::Ciphertext,
        rhs: &Self::Ciphertext,
    ) {
        match operation {
            BfvHOperation2::Add => {
                impls::homom_add_inplace(&self.evaluator, &mut lhs.0, &rhs.0);
            }
            BfvHOperation2::Mul => {
                impls::homom_mul_inplace(&self.evaluator, &mut lhs.0, &rhs.0);
            }
        }
    }

    fn relinearize(&self, _ciphertext: &mut Self::Ciphertext) {
        // No relinearization in BFV
    }
}

impl SelectableCS for SealBfvCS {
    const ADD_OPP: Self::Operation2 = BfvHOperation2::Add;
    const MUL_OPP: Self::Operation2 = BfvHOperation2::Mul;

    fn flag_to_plaintext(&self, flag: Flag) -> Self::Plaintext {
        const FLAG_ON: u64 = 1;
        const FLAG_OFF: u64 = 0;

        match flag {
            Flag::On => FLAG_ON,
            Flag::Off => FLAG_OFF,
        }
    }
}

#[derive(Clone, Copy, Debug, Encode, Decode)]
#[non_exhaustive]
pub enum BfvHOperation1 {
    AddPlain(u64),
    MulPlain(u64),
    Exp(u64),
}
impl Operation for BfvHOperation1 {}
impl Arity1Operation for BfvHOperation1 {}

#[derive(Clone, Copy, Debug, Encode, Decode)]
#[non_exhaustive]
pub enum BfvHOperation2 {
    Add,
    Mul,
}
impl Operation for BfvHOperation2 {}
impl Arity2Operation for BfvHOperation2 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{SealBFVContext, SealCkksContext};
    use fhe_core::{api::CryptoSystem, f64::approx_eq};

    const PRECISION: f64 = 5e-2;

    #[test]
    fn test_seal_ckks_cs() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(&context, 1e6);

        let a = cs.cipher(&1.0);
        let b = cs.cipher(&2.0);
        let c = cs.operate2(CkksHOperation2::Add, &a, &b);
        let d = cs.operate2(CkksHOperation2::Mul, &a, &b);

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
    fn test_seal_ckks_cs_plain_ops() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(&context, 1e6);

        let a = cs.cipher(&1.0);
        let b = cs.cipher(&2.0);
        let c = cs.operate1(CkksHOperation1::AddPlain(10.0), &a);
        let d = cs.operate1(CkksHOperation1::MulPlain(2.0), &b);

        let c = cs.decipher(&c);
        let d = cs.decipher(&d);

        assert!(approx_eq(c, 11.0, PRECISION));
        assert!(approx_eq(d, 4.0, PRECISION));
    }

    #[test]
    fn test_seal_ckks_cs_linear_sum() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(&context, 1e6);

        let a_plaintext = 1.0;
        let a_coeff_plaintext = 2.0;
        let b_plaintext = 3.0;
        let b_coeff_plaintext = 4.0;

        let a = cs.cipher(&a_plaintext);
        let a_coeff = cs.cipher(&a_coeff_plaintext);
        let b = cs.cipher(&b_plaintext);
        let b_coeff = cs.cipher(&b_coeff_plaintext);
        let ac = cs.operate2(CkksHOperation2::Mul, &a, &a_coeff);
        let bc = cs.operate2(CkksHOperation2::Mul, &b, &b_coeff);
        let sum = cs.operate2(CkksHOperation2::Add, &ac, &bc);

        let decrypted_sum = cs.decipher(&sum);
        let expected_sum = a_plaintext * a_coeff_plaintext + b_plaintext * b_coeff_plaintext;

        assert!(approx_eq(decrypted_sum, expected_sum, 5e-2))
    }

    #[test]
    fn test_seal_bfv_cs() {
        let context = SealBFVContext::new(DegreeType::D2048, SecurityLevel::TC128, 16);
        let cs = SealBfvCS::new(&context);

        let a_plaintext = 1;
        let b_plaintext = 2;

        let a = cs.cipher(&a_plaintext);
        let b = cs.cipher(&b_plaintext);
        let c = cs.operate2(BfvHOperation2::Add, &a, &b);
        let d = cs.operate2(BfvHOperation2::Mul, &a, &b);

        let a = cs.decipher(&a);
        let b = cs.decipher(&b);
        let c = cs.decipher(&c);
        let d = cs.decipher(&d);

        assert_eq!(a, a_plaintext);
        assert_eq!(b, b_plaintext);
        assert_eq!(c, a_plaintext + b_plaintext);
        assert_eq!(d, a_plaintext * b_plaintext);
    }

    #[test]
    fn test_seal_bfv_cs_plain_ops() {
        let context = SealBFVContext::new(DegreeType::D2048, SecurityLevel::TC128, 16);
        let cs = SealBfvCS::new(&context);

        let a = cs.cipher(&1);
        let b = cs.cipher(&2);
        let c = cs.operate1(BfvHOperation1::AddPlain(10), &a);
        let d = cs.operate1(BfvHOperation1::MulPlain(2), &b);

        let c = cs.decipher(&c);
        let d = cs.decipher(&d);

        assert_eq!(c, 11);
        assert_eq!(d, 4);
    }

    #[test]
    fn test_seal_bfv_cs_exp() {
        let context = SealBFVContext::new(DegreeType::D4096, SecurityLevel::TC128, 16);
        let cs = SealBfvCS::new(&context);

        let a = cs.cipher(&4);
        let e = cs.operate1(BfvHOperation1::Exp(2), &a);

        let d = cs.decipher(&e);

        assert_eq!(d, 16);
    }
}
