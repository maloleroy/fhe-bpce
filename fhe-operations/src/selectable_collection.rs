//! SQL-like operations on encrypted data.

use bincode::{Decode, Encode};
use fhe_core::api::CryptoSystem;

/// A `CryptoSystem` that can be used to perform selection operations.
pub trait SelectableCS: CryptoSystem {
    /// The operation that adds two ciphertexts.
    const ADD_OPP: Self::Operation2;
    /// The operation that multiplies two ciphertexts.
    const MUL_OPP: Self::Operation2;

    /// The plaintext that is neutral with respect to addition.
    const NEUTRAL_ADD: Self::Plaintext;
    /// The plaintext that is neutral with respect to multiplication.
    const NEUTRAL_MUL: Self::Plaintext;
}

/// A flag that can be used to select items.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flag {
    On,
    Off,
}

/// A selectable item that can be used in a collection.
pub struct SelectableItem<const F: usize, C: CryptoSystem> {
    ciphertext: C::Ciphertext,
    flags: [C::Ciphertext; F],
}

impl<C: CryptoSystem, const F: usize> Encode for SelectableItem<F, C>
where
    C::Ciphertext: Encode,
{
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.ciphertext.encode(encoder)?;
        self.flags.encode(encoder)
    }
}

impl<C: CryptoSystem, const F: usize, Context> Decode<Context> for SelectableItem<F, C>
where
    C::Ciphertext: Encode + Decode<Context>,
{
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let ciphertext = C::Ciphertext::decode(decoder)?;
        let flags = <[C::Ciphertext; F]>::decode(decoder)?;
        Ok(Self { ciphertext, flags })
    }
}

#[must_use]
#[inline]
const fn flag_to_plaintext<C: SelectableCS>(flag: Flag) -> C::Plaintext {
    match flag {
        Flag::On => C::NEUTRAL_MUL,
        Flag::Off => C::NEUTRAL_ADD,
    }
}

impl<const F: usize, C: SelectableCS> SelectableItem<F, C> {
    #[must_use]
    pub fn new(value: &C::Plaintext, cs: &C) -> Self {
        const DEFAULT_FLAG: Flag = Flag::Off;
        let default_flag = flag_to_plaintext::<C>(DEFAULT_FLAG);
        Self {
            ciphertext: cs.cipher(value),
            flags: core::array::from_fn(|_| cs.cipher(&default_flag)),
        }
    }

    #[must_use]
    #[inline]
    fn get_flag(&self, index: usize) -> Option<&C::Ciphertext> {
        self.flags.get(index)
    }

    #[must_use]
    #[inline]
    #[cfg(test)]
    fn get_flag_plain(&self, index: usize, cs: &C) -> C::Plaintext {
        cs.decipher(&self.flags[index])
    }

    #[inline]
    pub fn set_flag_plain(&mut self, index: usize, flag: Flag, cs: &C) {
        self.flags[index] = cs.cipher(&flag_to_plaintext::<C>(flag));
    }
}

/// A collection of `SelectableItem`s.
///
/// This is the collection used to perform the selection operations.
#[derive(Default)]
pub struct SelectableCollection<const F: usize, C: CryptoSystem> {
    items: Vec<SelectableItem<F, C>>,
}

impl<C: CryptoSystem, const F: usize> Encode for SelectableCollection<F, C>
where
    C::Ciphertext: Encode,
{
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.items.encode(encoder)
    }
}

impl<C: CryptoSystem, const F: usize, Context> Decode<Context> for SelectableCollection<F, C>
where
    C::Ciphertext: Encode + Decode<Context>,
{
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let items = Vec::<SelectableItem<F, C>>::decode(decoder)?;
        Ok(Self { items })
    }
}

impl<const F: usize, C: SelectableCS<Ciphertext: Clone>> SelectableCollection<F, C> {
    #[must_use]
    #[inline]
    /// Create a new empty collection.
    pub const fn new() -> Self {
        Self { items: Vec::new() }
    }

    #[must_use]
    #[inline]
    /// Get the number of items in the collection.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    #[inline]
    /// Check if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    #[inline]
    /// Add an item to the collection.
    pub fn push(&mut self, item: SelectableItem<F, C>) {
        self.items.push(item);
    }

    #[inline]
    /// Add a plaintext item to the collection.
    /// This plaintext will be ciphered using the given `CryptoSystem`.
    pub fn push_plain(&mut self, item: &C::Plaintext, cs: &C) {
        self.items.push(SelectableItem::new(item, cs));
    }

    #[must_use]
    /// Operates on all items in the collection.
    pub fn operate_many(&self, op: C::Operation2, cs: &C) -> C::Ciphertext
    where
        C::Operation2: Copy,
    {
        let mut sum: C::Ciphertext = self.items[0].ciphertext.clone();
        for i in 1..self.items.len() {
            sum = cs.operate2(op, &sum, &self.items[i].ciphertext).clone();
        }
        sum
    }

    #[must_use]
    /// Operates on all items in the collection where the flag at the given index is set to `Flag::On`.
    ///
    /// ## Panics
    ///
    /// Panics if the collection is empty.
    pub fn operate_many_where_flag(&self, flag_index: usize, cs: &C) -> C::Ciphertext
    where
        C::Operation2: Copy,
    {
        assert!(!self.items.is_empty());

        let first_item = &self.items[0];
        let first_flag = first_item.get_flag(flag_index).unwrap();
        let mut sum: C::Ciphertext = cs.operate2(C::MUL_OPP, &first_item.ciphertext, first_flag);

        for item in self.items.iter().skip(1) {
            let flag = item.get_flag(flag_index).unwrap();
            let product = cs.operate2(C::MUL_OPP, &item.ciphertext, flag);
            sum = cs.operate2(C::ADD_OPP, &sum, &product).clone();
        }
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe_core::api::{Arity2Operation, Operation};
    const F: usize = 2;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    struct TestPlaintext(u64);
    #[derive(Clone)]
    struct TestCiphertext {
        // Absolutely not secure system, just for testing purposes.
        data: TestPlaintext,
    }

    struct TestCryptoSystem {}

    #[derive(Clone, Copy, Debug)]
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
    impl SelectableCS for TestCryptoSystem {
        const ADD_OPP: Self::Operation2 = Op::Add;
        const MUL_OPP: Self::Operation2 = Op::Mul;

        const NEUTRAL_ADD: Self::Plaintext = TestPlaintext(0);
        const NEUTRAL_MUL: Self::Plaintext = TestPlaintext(1);
    }

    #[test]
    fn test_collection_new() {
        // let context = SealCkksContext::new(DegreeType::D4096, SecurityLevel::TC128);
        // let _cs = SealCkksCS::new(context, 1e6);

        let collection = SelectableCollection::<F, TestCryptoSystem>::new();
        assert_eq!(collection.len(), 0);
    }

    #[test]
    fn test_collection_push() {
        let cs = TestCryptoSystem {};
        let mut collection = SelectableCollection::<F, TestCryptoSystem>::new();
        let item = SelectableItem::new(&TestPlaintext(1), &cs);
        collection.push(item);
        assert_eq!(collection.len(), 1);
    }

    #[test]
    fn test_collection_push_plain() {
        let cs = TestCryptoSystem {};
        let mut collection = SelectableCollection::<F, TestCryptoSystem>::new();
        let item = SelectableItem::new(&TestPlaintext(1), &cs);
        collection.push(item);
        assert_eq!(collection.len(), 1);
    }

    #[test]
    fn test_is_empty() {
        let cs = TestCryptoSystem {};
        let mut collection = SelectableCollection::<F, TestCryptoSystem>::new();
        assert!(collection.is_empty());
        let item = SelectableItem::new(&TestPlaintext(1), &cs);
        collection.push(item);
        assert!(!collection.is_empty());
    }

    #[test]
    fn test_push_plain() {
        let cs = TestCryptoSystem {};
        let mut collection = SelectableCollection::<F, TestCryptoSystem>::new();
        let item = SelectableItem::new(&TestPlaintext(1), &cs);
        collection.push(item);
        assert_eq!(collection.len(), 1);
    }

    #[test]
    fn test_operate_many() {
        let cs = TestCryptoSystem {};
        let mut collection = SelectableCollection::<F, _>::new();
        let item = SelectableItem::new(&TestPlaintext(1), &cs);
        collection.push(item);
        let item = SelectableItem::new(&TestPlaintext(2), &cs);
        collection.push(item);
        let sum = collection.operate_many(Op::Add, &cs);
        let decrypted = cs.decipher(&sum);
        assert_eq!(decrypted.0, 3);
    }

    #[test]
    fn test_get_flag_plain() {
        let cs = TestCryptoSystem {};
        let item = SelectableItem::<2, TestCryptoSystem>::new(&TestPlaintext(1), &cs);
        assert_eq!(item.get_flag_plain(0, &cs), TestPlaintext(0));
    }

    #[test]
    fn test_set_flag_plain() {
        let cs = TestCryptoSystem {};
        let mut item = SelectableItem::<2, TestCryptoSystem>::new(&TestPlaintext(1), &cs);
        item.set_flag_plain(0, Flag::On, &cs);
        assert_eq!(item.get_flag_plain(0, &cs), TestPlaintext(1));
    }

    #[test]
    fn test_operate_many_where_flag() {
        let cs = TestCryptoSystem {};
        let mut collection = SelectableCollection::<F, _>::new();

        let item = SelectableItem::new(&TestPlaintext(1), &cs);
        collection.push(item);
        collection.items[0].set_flag_plain(0, Flag::On, &cs);
        let item = SelectableItem::new(&TestPlaintext(2), &cs);
        collection.push(item);

        let sum = collection.operate_many_where_flag(0, &cs);
        let decrypted = cs.decipher(&sum);

        let expected = TestPlaintext(1);

        assert_eq!(decrypted, expected);
    }
}
