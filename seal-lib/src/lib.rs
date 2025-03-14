//! Convenient wrapper around Microsoft SEAL library.

pub mod context;
pub use bincode::{Decode, Encode};
use context::CkksContext;
pub use sealy::{
    BFVEncoder, BFVEvaluator, CKKSEncoder, CKKSEvaluator, Decryptor, DegreeType, Plaintext,
    SecurityLevel,
};
use sealy::{FromBytes, ToBytes};

pub type Encryptor = sealy::Encryptor<sealy::Asym>;

pub struct Ciphertext(sealy::Ciphertext);

impl Ciphertext {
    pub fn new(encryptor: &Encryptor, x: &Plaintext) -> Self {
        Self(encryptor.encrypt(x).unwrap())
    }

    pub fn decrypt(&self, decryptor: &Decryptor) -> Plaintext {
        decryptor.decrypt(&self.0).unwrap()
    }
}

impl Encode for Ciphertext {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.0.as_bytes().unwrap().encode(encoder)
    }
}

impl Decode<CkksContext> for Ciphertext {
    fn decode<D: bincode::de::Decoder<Context = CkksContext>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let raw: Vec<_> = Decode::decode(decoder)?;
        Ok(Self(
            sealy::Ciphertext::from_bytes(&decoder.context().context(), &raw).unwrap(),
        ))
    }
}
