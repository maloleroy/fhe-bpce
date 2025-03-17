use bincode::{Decode, Encode};
use fhe_core::api::CryptoSystem;

/// The data that will be exchanged by the client and the server.
pub struct ExchangeData<C: CryptoSystem>
where
    C::CiphertextHandle: Encode,
    C::Operation: Encode,
{
    lhs: Vec<C::CiphertextHandle>,
    rhs: Vec<Option<C::CiphertextHandle>>,
    operation: Vec<C::Operation>,
}

impl<C: CryptoSystem> ExchangeData<C>
where
    C::CiphertextHandle: Encode,
    C::Operation: Encode,
{
    /// Creates a new instance of `ExchangeData`.
    pub fn new(
        lhs: Vec<C::CiphertextHandle>,
        rhs: Vec<Option<C::CiphertextHandle>>,
        operation: Vec<C::Operation>,
    ) -> Self {
        Self {
            lhs,
            rhs,
            operation,
        }
    }

    /// Returns the number of exchanged data.
    pub fn len(&self) -> usize {
        assert_eq!(self.lhs.len(), self.rhs.len());
        assert_eq!(self.lhs.len(), self.operation.len());
        self.lhs.len()
    }

    /// Returns `true` if the exchanged data is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over the exchanged data.
    pub fn iter_over_data(
        &self,
    ) -> impl Iterator<
        Item = (
            &C::CiphertextHandle,
            Option<&C::CiphertextHandle>,
            &C::Operation,
        ),
    > {
        self.lhs
            .iter()
            .zip(self.rhs.iter())
            .zip(self.operation.iter())
            .map(|((lhs, rhs), operation)| (lhs, rhs.as_ref(), operation))
    }
}

impl<C: CryptoSystem> Encode for ExchangeData<C>
where
    C::CiphertextHandle: Encode,
    C::Operation: Encode,
{
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.lhs.encode(encoder)?;
        self.rhs.encode(encoder)?;
        self.operation.encode(encoder)
    }
}

impl<C: CryptoSystem, Context> Decode<Context> for ExchangeData<C>
where
    C::CiphertextHandle: Decode<Context> + Encode,
    C::Operation: Decode<Context> + Encode,
{
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Ok(Self {
            lhs: Vec::<_>::decode(decoder)?,
            rhs: Vec::<Option<_>>::decode(decoder)?,
            operation: Vec::<_>::decode(decoder)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::config::Configuration;
    use seal_lib::{Ciphertext, DegreeType, SealBfvCS, SecurityLevel, context::SealBFVContext};

    const CONFIG: Configuration = bincode::config::standard();

    #[test]
    fn test_seal_bfv_cs() {
        let context = SealBFVContext::new(
            DegreeType::D2048,
            DegreeType::D2048,
            SecurityLevel::TC128,
            DegreeType::D2048,
            25,
        );
        let cs = SealBfvCS::new(context.clone());

        let a = cs.cipher(&1);

        // Data that would be send to the server
        let a_encoded = bincode::encode_to_vec(a, CONFIG).unwrap();

        let (a_decoded, _): (Ciphertext, _) =
            bincode::decode_from_slice_with_context(a_encoded.as_slice(), CONFIG, context).unwrap();
        let a_final = cs.decipher(&a_decoded);

        assert_eq!(*a_final, 1);
    }
}
