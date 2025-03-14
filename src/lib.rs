//! Homomorphic encryption library for Rust.
#![warn(clippy::nursery, clippy::pedantic)]
#![forbid(unsafe_code)]

pub mod ops;

use bincode::{Decode, Encode};

#[derive(Encode)]
#[non_exhaustive]
/// A wrapper around the different homomorphic encryption ciphertexts.
pub enum Ciphertext {
    Seal(seal_lib::Ciphertext),
}

#[derive(Clone)]
#[non_exhaustive]
/// A wrapper around the different homomorphic encryption contexts.
pub enum Context {
    Seal(seal_lib::context::CkksContext),
}

#[non_exhaustive]
pub enum Encryptor {
    SealCkks {
        encoder: seal_lib::CKKSEncoder,
        encryptor: seal_lib::Encryptor,
    },
    SealBfv {
        encoder: seal_lib::BFVEncoder,
        encryptor: seal_lib::Encryptor,
    },
}

#[non_exhaustive]
pub enum Decryptor {
    Seal(seal_lib::Decryptor),
}

#[non_exhaustive]
pub enum Evaluator {
    SealCkks(seal_lib::CKKSEvaluator),
    SealBfv(seal_lib::BFVEvaluator),
}

impl Decode<Context> for Ciphertext {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let ctx = decoder.context().clone();
        match ctx {
            Context::Seal(seal_ctx) => {
                let mut dc = decoder.with_context(seal_ctx);
                Ok(Self::Seal(Decode::decode(&mut dc)?))
            }
        }
    }
}

#[derive(Encode)]
/// The data that will be exchanged by the client and the server.
struct ExchangeData {
    lhs: Vec<Ciphertext>,
    rhs: Vec<Option<Ciphertext>>,
    operation: Vec<ops::Operation>,
}

impl Decode<Context> for ExchangeData {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Ok(Self {
            lhs: Vec::<Ciphertext>::decode(decoder)?,
            rhs: Vec::<Option<Ciphertext>>::decode(decoder)?,
            operation: Vec::<ops::Operation>::decode(decoder)?,
        })
    }
}
