//! Sequentially executed operations.

use bincode::{Decode, Encode};
use fhe_core::api::CryptoSystem;

pub struct SeqOpItem<C: CryptoSystem>
where
    C::Ciphertext: Encode,
    C::Operation2: Encode,
{
    lhs: C::Ciphertext,
    rhs: C::Ciphertext,
    operation: C::Operation2,
}

impl<C: CryptoSystem> SeqOpItem<C>
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
    /// Executes the operation.
    pub fn execute(&self, cs: &C) -> C::Ciphertext
    where
        C::Operation2: Copy,
    {
        cs.operate2(self.operation, &self.lhs, &self.rhs)
    }
}

impl<C: CryptoSystem> Encode for SeqOpItem<C>
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

impl<C: CryptoSystem, Context> Decode<Context> for SeqOpItem<C>
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
pub struct SeqOpsData<C: CryptoSystem>(Vec<SeqOpItem<C>>)
where
    C::Ciphertext: Encode,
    C::Operation2: Encode;

impl<C: CryptoSystem> SeqOpsData<C>
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
    pub fn push(&mut self, item: SeqOpItem<C>) {
        self.0.push(item);
    }

    #[must_use]
    #[inline]
    /// Creates a new instance of `ExchangeData`.
    pub const fn from_vec(data: Vec<SeqOpItem<C>>) -> Self {
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
    pub fn iter_over_data(&self) -> impl Iterator<Item = &SeqOpItem<C>> {
        self.0.iter()
    }
}

impl<C: CryptoSystem> Encode for SeqOpsData<C>
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

impl<C: CryptoSystem, Context> Decode<Context> for SeqOpsData<C>
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
    use fhe_core::api::{Arity2Operation, Operation};

    const CONFIG: Configuration = bincode::config::standard();

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
    struct TestPlaintext(u64);
    #[derive(Clone, Encode, Decode)]
    struct TestCiphertext {
        // Absolutely not secure system, just for testing purposes.
        data: TestPlaintext,
    }

    struct TestCryptoSystem {}

    #[derive(Clone, Copy, Debug)]
    #[allow(dead_code)]
    enum Op {
        Add,
        Mul,
    }
    impl Operation for Op {}
    impl Arity2Operation for Op {}

    impl CryptoSystem for TestCryptoSystem {
        type Plaintext = TestPlaintext;
        type Ciphertext = TestCiphertext;
        type Operation1 = ();
        type Operation2 = Op;

        fn cipher(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
            TestCiphertext {
                data: plaintext.clone(),
            }
        }
        fn decipher(&self, ciphertext: &Self::Ciphertext) -> Self::Plaintext {
            ciphertext.data.clone()
        }

        fn operate1(
            &self,
            _operation: Self::Operation1,
            lhs: &Self::Ciphertext,
        ) -> Self::Ciphertext {
            TestCiphertext {
                data: lhs.data.clone(),
            }
        }

        fn operate2(
            &self,
            operation: Self::Operation2,
            lhs: &Self::Ciphertext,
            rhs: &Self::Ciphertext,
        ) -> Self::Ciphertext {
            match operation {
                Op::Add => TestCiphertext {
                    data: TestPlaintext(lhs.data.0 + rhs.data.0),
                },
                Op::Mul => TestCiphertext {
                    data: TestPlaintext(lhs.data.0 * rhs.data.0),
                },
            }
        }

        fn relinearize(&self, _ciphertext: &mut Self::Ciphertext) {}
    }

    #[test]
    fn test_seal_bfv_cs() {
        let cs = TestCryptoSystem {};

        let a = cs.cipher(&TestPlaintext(1));

        // Data that would be send to the server
        let a_encoded = bincode::encode_to_vec(a, CONFIG).unwrap();

        let (a_decoded, _): (TestCiphertext, _) =
            bincode::decode_from_slice(a_encoded.as_slice(), CONFIG).unwrap();
        let a_final = cs.decipher(&a_decoded);

        assert_eq!(a_final, TestPlaintext(1));
    }
}
