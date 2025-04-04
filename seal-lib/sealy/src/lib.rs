#![warn(clippy::nursery, clippy::pedantic)]
#![allow(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::doc_markdown
)]

#[cfg(not(target_arch = "wasm32"))]
extern crate link_cplusplus;

#[allow(non_camel_case_types)]
#[allow(unused)]
mod bindgen {
    use std::os::raw::c_long;

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

    pub const S_OK: c_long = 0x0;
    pub const E_POINTER: c_long = 0x8000_4003u32 as c_long;
    pub const E_INVALIDARG: c_long = 0x8007_0057u32 as c_long;
    pub const E_OUTOFMEMORY: c_long = 0x8007_000Eu32 as c_long;
    pub const E_UNEXPECTED: c_long = 0x8000_FFFFu32 as c_long;
    pub const COR_E_IO: c_long = 0x8013_1620u32 as c_long;
    pub const COR_E_INVALIDOPERATION: c_long = 0x8013_1509u32 as c_long;
}

mod ciphertext;
mod components;
mod context;
mod decryptor;
mod encoder;
mod encryptor;
mod error;
mod evaluator;
mod ext;
mod key_generator;
mod memory;
mod modulus;
mod parameters;
mod plaintext;
mod serialization;

pub use ciphertext::Ciphertext;
pub use components::{Asym, Sym, SymAsym, marker as component_marker};
pub use context::Context;
pub use decryptor::Decryptor;
pub use encoder::bfv::BFVEncoder;
pub use encoder::bgv::BGVEncoder;
pub use encoder::ckks::CKKSEncoder;
pub use encryptor::{AsymmetricEncryptor, Encryptor, SymmetricEncryptor};
pub use error::{Error, Result};
pub use evaluator::Evaluator;
pub use evaluator::bfv::BFVEvaluator;
pub use evaluator::bgv::BGVEvaluator;
pub use evaluator::ckks::CKKSEvaluator;
pub use ext::tensor::{
    FromChunk, Tensor, ToChunk, decryptor::TensorDecryptor, encoder::TensorEncoder,
    encryptor::TensorEncryptor, evaluator::TensorEvaluator,
};
pub use key_generator::{GaloisKey, KeyGenerator, PublicKey, RelinearizationKey, SecretKey};
pub use memory::MemoryPool;
pub use modulus::{
    CoefficientModulusFactory, DegreeType, Modulus, PlainModulusFactory, SecurityLevel,
};
pub use parameters::*;
pub use plaintext::Plaintext;
pub use serialization::{FromBytes, ToBytes};
