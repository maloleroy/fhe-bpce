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

pub enum ContextCreationParameters {
    SealCkks {
        pmod: seal_lib::DegreeType,
        cmod: seal_lib::DegreeType,
        sl: seal_lib::SecurityLevel,
    },
}

impl Context {
    pub fn new(creation_parameters: ContextCreationParameters) -> Self {
        match creation_parameters {
            ContextCreationParameters::SealCkks { pmod, cmod, sl } => {
                Self::Seal(seal_lib::context::CkksContext::new(pmod, cmod, sl))
            }
        }
    }
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

impl Encryptor {
    pub fn encrypt_f64(&self, x: f64) -> Ciphertext {
        match self {
            Self::SealCkks { encoder, encryptor } => {
                let x = encoder.encode_f64(&[x]).unwrap();
                Ciphertext::Seal(seal_lib::Ciphertext::new(encryptor, &x))
            }
            Self::SealBfv {
                encoder: _,
                encryptor: _,
            } => {
                panic!("BFV cannot be used to encrypt floats.")
            }
        }
    }
}

#[non_exhaustive]
pub enum Decryptor {
    SealCkks {
        encoder: seal_lib::CKKSEncoder,
        decryptor: seal_lib::Decryptor,
    },
    SealBfv {
        encoder: seal_lib::BFVEncoder,
        decryptor: seal_lib::Decryptor,
    },
}

impl Decryptor {
    pub fn decrypt_f64(&self, x: &Ciphertext) -> f64 {
        match self {
            Self::SealCkks { encoder, decryptor } => {
                let Ciphertext::Seal(ckks_x) = x;
                // else {
                //     panic!("Wrong ciphertext type.")
                // };
                let decrypted = ckks_x.decrypt(decryptor);
                encoder.decode_f64(&decrypted).unwrap()[0]
            }
            Self::SealBfv {
                encoder: _,
                decryptor: _,
            } => {
                panic!("BFV cannot be used to decrypt floats.")
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use seal_lib::{SecurityLevel, context::DegreeType};

    #[test]
    fn test_encryption() {
        let ctx = Context::new(ContextCreationParameters::SealCkks {
            pmod: DegreeType::D2048,
            cmod: DegreeType::D2048,
            sl: SecurityLevel::TC128,
        });
        let Context::Seal(seal_ctx) = ctx;

        let (skey, pkey) = seal_ctx.generate_keys();

        let encoder_e = seal_ctx.encoder(1e6);
        let encoder_d = seal_ctx.encoder(1e6);

        let decryptor = seal_ctx.decryptor(&skey);
        let encryptor = seal_ctx.encryptor(&pkey);

        let dec = Decryptor::SealCkks {
            encoder: encoder_d,
            decryptor,
        };
        let enc = Encryptor::SealCkks {
            encoder: encoder_e,
            encryptor,
        };

        let plaintext = 1.0;
        let ciphertext = enc.encrypt_f64(plaintext);
        let decrypted = dec.decrypt_f64(&ciphertext);

        println!("plaintext {}, decrypted: {}", plaintext, decrypted);
        assert!((plaintext - decrypted).abs() < 1e-2);
    }
}
