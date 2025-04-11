#![no_std]
#![forbid(unsafe_code)]
#![warn(clippy::nursery, clippy::pedantic)]
#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

extern crate alloc;

use bincode::{Decode, Encode, serde::Compat};
use core::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Not, Rem, Sub};
use fhe_core::api::{Arity1Operation, Arity2Operation, CryptoSystem, Operation};
use fhe_operations::selectable_collection::SelectableCS;
use serde::{Deserialize, Serialize};
use tfhe::{
    ClientKey,
    prelude::{FheDecrypt, FheEncrypt},
    set_server_key,
};
pub use tfhe::{
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256, FheInt512, FheInt1024, FheInt2048,
};
pub use tfhe::{
    FheUint8, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256, FheUint512, FheUint1024,
    FheUint2048,
};

pub mod config;

#[derive(Clone)]
/// Ciphertext from Zama TFHE
pub struct Ciphertext<T, I: FheEncrypt<T, tfhe::ClientKey>> {
    value: I,
    _phantom: core::marker::PhantomData<T>,
}

impl<T, I: FheEncrypt<T, tfhe::ClientKey> + Serialize> Encode for Ciphertext<T, I> {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        let compat_value = Compat(&self.value);
        compat_value.encode(encoder)
    }
}

#[allow(clippy::type_repetition_in_bounds)] // Readability
impl<Context, T, I: FheEncrypt<T, tfhe::ClientKey>> Decode<Context> for Ciphertext<T, I>
where
    for<'de> I: Deserialize<'de>,
{
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let compat_value = Compat::decode(decoder)?;

        Ok(Self {
            value: compat_value.0,
            _phantom: core::marker::PhantomData,
        })
    }
}

/// The TFHE CryptoSystem backed by Zama, for integers.
pub struct ZamaTfheCS<T, I: FheEncrypt<T, tfhe::ClientKey>> {
    client_key: Option<tfhe::ClientKey>,
    _phantom: core::marker::PhantomData<(T, I)>,
}

impl<T, I: FheEncrypt<T, tfhe::ClientKey>> ZamaTfheCS<T, I> {
    #[must_use]
    pub fn new(context: &config::ZamaTfheContext) -> Self {
        let (client_key, secret_key) = context.generate_keys();
        set_server_key(secret_key.0);
        Self {
            client_key,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<T: Copy, I: FheEncrypt<T, ClientKey> + FheDecrypt<T> + Clone> CryptoSystem for ZamaTfheCS<T, I>
where
    I: Add<Output = I>
        + Mul<Output = I>
        + Neg<Output = I>
        + Div<Output = I>
        + Rem<Output = I>
        + Sub<Output = I>
        + Not<Output = I>
        + BitAnd<Output = I>
        + BitOr<Output = I>
        + BitXor<Output = I>,
{
    type Ciphertext = Ciphertext<T, I>;
    type Plaintext = T;
    type Operation1 = TfheHOperation1;
    type Operation2 = TfheHOperation2;

    fn cipher(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        let ciphertext = I::encrypt(*plaintext, self.client_key.as_ref().unwrap());
        Ciphertext {
            value: ciphertext,
            _phantom: core::marker::PhantomData,
        }
    }

    fn decipher(&self, ciphertext: &Self::Ciphertext) -> Self::Plaintext {
        ciphertext.value.decrypt(self.client_key.as_ref().unwrap())
    }

    fn operate1(&self, operation: Self::Operation1, lhs: &Self::Ciphertext) -> Self::Ciphertext {
        match operation {
            TfheHOperation1::Neg => {
                let result = -lhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
            }
            TfheHOperation1::Not => {
                let result = !lhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
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
            TfheHOperation2::Add => {
                let result = lhs.value.clone() + rhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
            }
            TfheHOperation2::Mul => {
                let result = lhs.value.clone() * rhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
            }
            TfheHOperation2::Sub => {
                let result = lhs.value.clone() - rhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
            }
            TfheHOperation2::Div => {
                let result = lhs.value.clone() / rhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
            }
            TfheHOperation2::Rem => {
                let result = lhs.value.clone() % rhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
            }
            TfheHOperation2::And => {
                let result = lhs.value.clone() & rhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
            }
            TfheHOperation2::Or => {
                let result = lhs.value.clone() | rhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
            }
            TfheHOperation2::Xor => {
                let result = lhs.value.clone() ^ rhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
            }
        }
    }

    #[inline]
    fn relinearize(&self, _ciphertext: &mut Self::Ciphertext) {
        // No-op
    }
}

macro_rules! impl_selectable_cs {
    ($ty:ty) => {
        impl<I: FheEncrypt<$ty, ClientKey> + FheDecrypt<$ty> + Clone> SelectableCS
            for ZamaTfheCS<$ty, I>
        where
            I: Add<Output = I>
                + Mul<Output = I>
                + Neg<Output = I>
                + Div<Output = I>
                + Rem<Output = I>
                + Sub<Output = I>
                + Not<Output = I>
                + BitAnd<Output = I>
                + BitOr<Output = I>
                + BitXor<Output = I>,
        {
            const ADD_OPP: Self::Operation2 = TfheHOperation2::Add;
            const MUL_OPP: Self::Operation2 = TfheHOperation2::Mul;

            const NEUTRAL_ADD: Self::Plaintext = 0;
            const NEUTRAL_MUL: Self::Plaintext = 1;
        }
    };
}

impl_selectable_cs!(u8);
impl_selectable_cs!(u16);
impl_selectable_cs!(u32);
impl_selectable_cs!(u64);
impl_selectable_cs!(u128);
impl_selectable_cs!(i8);
impl_selectable_cs!(i16);
impl_selectable_cs!(i32);
impl_selectable_cs!(i64);
impl_selectable_cs!(i128);

#[derive(Clone, Copy, Debug, Encode, Decode)]
#[non_exhaustive]
pub enum TfheHOperation1 {
    Neg,
    Not,
    // TODO: Add more operations:
    // <https://docs.zama.ai/tfhe-rs/fhe-computation/operations>
}
impl Operation for TfheHOperation1 {}
impl Arity1Operation for TfheHOperation1 {}

#[derive(Clone, Copy, Debug, Encode, Decode)]
#[non_exhaustive]
pub enum TfheHOperation2 {
    Add,
    Mul,
    Sub,
    Div,
    Rem,
    And,
    Or,
    Xor,
    // TODO: Add more operations:
    // <https://docs.zama.ai/tfhe-rs/fhe-computation/operations>
}
impl Operation for TfheHOperation2 {}
impl Arity2Operation for TfheHOperation2 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ZamaTfheContext;

    const CONFIG: bincode::config::Configuration = bincode::config::standard();

    #[test]
    fn test_tfhe_uint() {
        let context = ZamaTfheContext::new();
        let cs = ZamaTfheCS::<u8, FheUint8>::new(&context);

        let a = cs.cipher(&27);
        let b = cs.cipher(&128);

        let result = cs.operate2(TfheHOperation2::Add, &a, &b);

        let decrypted_result = cs.decipher(&result);

        let clear_result = 27 + 128;

        assert_eq!(decrypted_result, clear_result);
    }

    #[test]
    fn test_tfhe_int() {
        let context = ZamaTfheContext::new();
        let cs = ZamaTfheCS::<i8, FheInt8>::new(&context);

        let a = cs.cipher(&27);
        let b = cs.cipher(&127);

        let result = cs.operate2(TfheHOperation2::Sub, &a, &b);

        let decrypted_result = cs.decipher(&result);

        let clear_result = 27 - 127;

        assert_eq!(decrypted_result, clear_result);
    }

    #[test]
    fn test_tfhe_encode_decode() {
        let context = ZamaTfheContext::new();
        let cs = ZamaTfheCS::<u8, FheUint8>::new(&context);

        let a = cs.cipher(&27);

        let a_encoded = bincode::encode_to_vec(a, CONFIG).unwrap();
        let (a_decoded, _) = bincode::decode_from_slice(&a_encoded, CONFIG).unwrap();

        let decrypted_a = cs.decipher(&a_decoded);

        assert_eq!(decrypted_a, 27);
    }
}
