//! Convenient wrapper around Microsoft SEAL library.
#![no_std]

extern crate alloc;

use bincode::{Decode, Encode};
use core::ops::{Add, Div, Mul, Neg, Rem, Sub};
use fhe_core::api::{CryptoSystem, select::SelectableCS};
use tfhe::{
    ClientKey,
    prelude::{FheDecrypt, FheEncrypt},
    set_server_key,
};
pub use tfhe::{FheUint8, FheUint16, FheUint32, FheUint64, FheUint128};

pub mod config;

#[derive(Clone)]
/// Ciphertext from Microsoft SEAL.
pub struct Ciphertext<T, I: FheEncrypt<T, tfhe::ClientKey>> {
    value: I,
    _phantom: core::marker::PhantomData<T>,
}

impl<T, I: FheEncrypt<T, tfhe::ClientKey> + Encode> Encode for Ciphertext<T, I> {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.value.encode(encoder)
    }
}

impl<Context, T, I: FheEncrypt<T, tfhe::ClientKey> + Encode + Decode<Context>> Decode<Context>
    for Ciphertext<T, I>
{
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Ok(Self {
            value: I::decode(decoder)?,
            _phantom: core::marker::PhantomData,
        })
    }
}

/// The TFHE CryptoSystem backed by Zama, for unsigned integers.
pub struct ZamaTfheUintCS<T, I: FheEncrypt<T, tfhe::ClientKey>> {
    client_key: Option<tfhe::ClientKey>,
    _phantom: core::marker::PhantomData<(T, I)>,
}

impl<T, I: FheEncrypt<T, tfhe::ClientKey>> ZamaTfheUintCS<T, I> {
    pub fn new(context: config::ZamaTfheContext) -> Self {
        let (client_key, secret_key) = context.generate_keys();
        set_server_key(secret_key.0.clone());
        Self {
            client_key,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<
    T: Copy,
    I: FheEncrypt<T, ClientKey> + FheDecrypt<T> + Add + Mul + Neg + Div + Rem + Sub + Clone,
> CryptoSystem for ZamaTfheUintCS<T, I>
where
    I: Add<Output = I>,
    I: Mul<Output = I>,
    I: Neg<Output = I>,
    I: Div<Output = I>,
    I: Rem<Output = I>,
    I: Sub<Output = I>,
{
    type Ciphertext = Ciphertext<T, I>;
    type Plaintext = T;
    type Operation = TfheHOperation;

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

    fn operate(
        &self,
        operation: Self::Operation,
        lhs: &Self::Ciphertext,
        rhs: Option<&Self::Ciphertext>,
    ) -> Self::Ciphertext {
        match operation {
            TfheHOperation::Add => {
                let rhs = rhs.expect("Addition requires two operands.");
                let result = lhs.value.clone() + rhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
            }
            TfheHOperation::Mul => {
                let rhs = rhs.expect("Multiplication requires two operands.");
                let result = lhs.value.clone() * rhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
            }
            TfheHOperation::Neg => {
                debug_assert!(rhs.is_none(), "Negation requires one operand.");
                let result = -lhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
            }
            TfheHOperation::Sub => {
                let rhs = rhs.expect("Subtraction requires two operands.");
                let result = lhs.value.clone() - rhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
            }
            TfheHOperation::Div => {
                let rhs = rhs.expect("Division requires two operands.");
                let result = lhs.value.clone() / rhs.value.clone();
                Ciphertext {
                    value: result,
                    _phantom: core::marker::PhantomData,
                }
            }
            TfheHOperation::Rem => {
                let rhs = rhs.expect("Remainder requires two operands.");
                let result = lhs.value.clone() % rhs.value.clone();
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

impl<I: FheEncrypt<u64, ClientKey> + FheDecrypt<u64> + Add + Mul + Neg + Div + Rem + Sub + Clone>
    SelectableCS for ZamaTfheUintCS<u64, I>
where
    I: Add<Output = I>,
    I: Mul<Output = I>,
    I: Neg<Output = I>,
    I: Div<Output = I>,
    I: Rem<Output = I>,
    I: Sub<Output = I>,
{
    fn flag_to_plaintext(&self, flag: fhe_core::api::select::Flag) -> Self::Plaintext {
        const FLAG_ON: u64 = 1;
        const FLAG_OFF: u64 = 0;

        match flag {
            fhe_core::api::select::Flag::On => FLAG_ON,
            fhe_core::api::select::Flag::Off => FLAG_OFF,
        }
    }
}

#[derive(Clone, Copy, Debug, Encode, Decode)]
#[non_exhaustive]
pub enum TfheHOperation {
    Add,
    Mul,
    Neg,
    Sub,
    Div,
    Rem,
    // TODO: Add more operations:
    // <https://docs.zama.ai/tfhe-rs/fhe-computation/operations>
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ZamaTfheContext;

    #[test]
    fn test_tfhe() {
        let context = ZamaTfheContext::new();
        let cs = ZamaTfheUintCS::<u8, FheUint8>::new(context);

        let a = cs.cipher(&27);
        let b = cs.cipher(&128);

        let result = cs.operate(TfheHOperation::Add, &a, Some(&b));

        let decrypted_result = cs.decipher(&result);

        let clear_result = 27 + 128;

        assert_eq!(decrypted_result, clear_result);
    }
}
