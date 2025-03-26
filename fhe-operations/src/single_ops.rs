use bincode::{Decode, Encode};
use fhe_core::api::CryptoSystem;

pub struct SingleOpItem<C: CryptoSystem>
where
    C::Ciphertext: Encode,
    C::Operation2: Encode,
{
    lhs: C::Ciphertext,
    rhs: C::Ciphertext,
    operation: C::Operation2,
}

impl<C: CryptoSystem> SingleOpItem<C>
where
    C::Ciphertext: Encode,
    C::Operation2: Encode,
{
    #[must_use]
    #[inline]
    /// Creates a new instance of `SingleOpItem`.
    pub const fn new(lhs: C::Ciphertext, rhs: C::Ciphertext, operation: C::Operation2) -> Self {
        Self {
            lhs,
            rhs,
            operation,
        }
    }

    #[must_use]
    #[inline]
    pub const fn op(&self) -> &C::Operation2 {
        &self.operation
    }

    #[must_use]
    #[inline]
    pub const fn lhs(&self) -> &C::Ciphertext {
        &self.lhs
    }

    #[must_use]
    #[inline]
    pub const fn rhs(&self) -> &C::Ciphertext {
        &self.rhs
    }

    #[must_use]
    #[inline]
    pub fn execute(&self, cs: &C) -> C::Ciphertext
    where
        C::Operation2: Copy,
    {
        cs.operate2(self.operation, &self.lhs, &self.rhs)
    }
}

impl<C: CryptoSystem> Encode for SingleOpItem<C>
where
    C::Ciphertext: Encode,
    C::Operation2: Encode,
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

impl<C: CryptoSystem, Context> Decode<Context> for SingleOpItem<C>
where
    C::Ciphertext: Decode<Context> + Encode,
    C::Operation2: Decode<Context> + Encode,
{
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let lhs = C::Ciphertext::decode(decoder)?;
        let rhs = C::Ciphertext::decode(decoder)?;
        let operation = C::Operation2::decode(decoder)?;
        Ok(Self {
            lhs,
            rhs,
            operation,
        })
    }
}

#[derive(Default)]
/// The data that will be exchanged by the client and the server, for
/// sequential single operations.
pub struct SingleOpsData<C: CryptoSystem>(Vec<SingleOpItem<C>>)
where
    C::Ciphertext: Encode,
    C::Operation2: Encode;

impl<C: CryptoSystem> SingleOpsData<C>
where
    C::Ciphertext: Encode,
    C::Operation2: Encode,
{
    #[must_use]
    #[inline]
    /// Creates a new instance of `SingleOpsData`.
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    #[inline]
    pub fn push(&mut self, item: SingleOpItem<C>) {
        self.0.push(item);
    }

    #[must_use]
    #[inline]
    /// Creates a new instance of `ExchangeData`.
    pub const fn from_vec(data: Vec<SingleOpItem<C>>) -> Self {
        Self(data)
    }

    #[must_use]
    #[inline]
    /// Returns the number of exchanged data.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    #[inline]
    /// Returns `true` if the exchanged data is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    /// Iterate over the exchanged data.
    pub fn iter_over_data(&self) -> impl Iterator<Item = &SingleOpItem<C>> {
        self.0.iter()
    }
}

impl<C: CryptoSystem> Encode for SingleOpsData<C>
where
    C::Ciphertext: Encode,
    C::Operation2: Encode,
{
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.0.encode(encoder)?;
        Ok(())
    }
}

impl<C: CryptoSystem, Context> Decode<Context> for SingleOpsData<C>
where
    C::Ciphertext: Decode<Context> + Encode,
    C::Operation2: Decode<Context> + Encode,
{
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Ok(Self(Vec::decode(decoder)?))
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
        let context = SealBFVContext::new(DegreeType::D2048, SecurityLevel::TC128, 25);
        let cs = SealBfvCS::new(&context);

        let a = cs.cipher(&1);

        // Data that would be send to the server
        let a_encoded = bincode::encode_to_vec(a, CONFIG).unwrap();

        let (a_decoded, _): (Ciphertext, _) =
            bincode::decode_from_slice_with_context(a_encoded.as_slice(), CONFIG, context).unwrap();
        let a_final = cs.decipher(&a_decoded);

        assert_eq!(a_final, 1);
    }
}
