//! Homomorphic encryption library for Rust.
#![warn(clippy::nursery, clippy::pedantic)]
#![forbid(unsafe_code)]

pub mod config;
pub mod ops;

use bincode::{Decode, Encode};

#[derive(Encode)]
pub enum Ciphertext {
    Seal(seal_lib::Ciphertext),
}

#[derive(Clone)]
pub enum Context {
    Seal(seal_lib::context::CkksContext),
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
struct ExchangeData {
    // FIXME: Replace with ciphertext struct
    lhs: Vec<Ciphertext>,
    rhs: Option<Vec<Ciphertext>>,
    operation: Vec<ops::Operation>,
}

impl Decode<Context> for ExchangeData {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let ctx = decoder.context().clone();
        let mut dc = decoder.with_context(ctx);

        Ok(Self {
            lhs: Vec::<Ciphertext>::decode(&mut dc)?,
            rhs: Option::<Vec<Ciphertext>>::decode(&mut dc)?,
            operation: Vec::<ops::Operation>::decode(&mut dc)?,
        })
    }
}
