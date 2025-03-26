use bincode::{Decode, Encode};
use fhe_core::api::{
    CryptoSystem,
    select::{Flag, SelectableCS},
};

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

impl<const F: usize, C: SelectableCS> SelectableItem<F, C> {
    #[must_use]
    pub fn new(value: &C::Plaintext, cs: &C) -> Self {
        const DEFAULT_FLAG: Flag = Flag::Off;
        let default_flag = cs.flag_to_plaintext(DEFAULT_FLAG);
        Self {
            ciphertext: cs.cipher(value),
            flags: core::array::from_fn(|_| cs.cipher(&default_flag)),
        }
    }

    #[must_use]
    #[inline]
    pub fn get_flag(&self, index: usize) -> Option<&C::Ciphertext> {
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
        self.flags[index] = cs.cipher(&cs.flag_to_plaintext(flag));
    }
}

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
    pub const fn new() -> Self {
        Self { items: Vec::new() }
    }

    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    #[inline]
    pub fn push(&mut self, item: SelectableItem<F, C>) {
        self.items.push(item);
    }

    #[inline]
    pub fn push_plain(&mut self, item: &C::Plaintext, cs: &C) {
        self.items.push(SelectableItem::new(item, cs));
    }

    #[must_use]
    pub fn operate_many(&self, op: C::Operation, cs: &C) -> C::Ciphertext
    where
        C::Operation: Copy,
    {
        let mut sum: C::Ciphertext = self.items[0].ciphertext.clone();
        for i in 1..self.items.len() {
            sum = cs
                .operate(op, &sum, Some(&self.items[i].ciphertext))
                .clone();
        }
        sum
    }

    #[must_use]
    /// Operates on all items in the collection where the flag at the given index is set to `Flag::On`.
    ///
    /// ## Panics
    ///
    /// Panics if the collection is empty.
    pub fn operate_many_where_flag(
        &self,
        op: C::Operation,
        flag_index: usize,
        select_op: C::Operation,
        cs: &C,
    ) -> C::Ciphertext
    where
        C::Operation: Copy,
    {
        assert!(!self.items.is_empty());

        let first_item = &self.items[0];
        let first_flag = first_item.get_flag(flag_index);
        let mut sum: C::Ciphertext = cs.operate(select_op, &first_item.ciphertext, first_flag);

        for item in self.items.iter().skip(1) {
            let flag = item.get_flag(flag_index);
            let product = cs.operate(select_op, &item.ciphertext, flag);
            sum = cs.operate(op, &sum, Some(&product)).clone();
        }
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe_core::f64::approx_eq;
    use seal_lib::{
        CkksHOperation, DegreeType, SealCkksCS, SecurityLevel, context::SealCkksContext,
    };
    const F: usize = 2;

    #[test]
    fn test_collection_new() {
        // let context = SealCkksContext::new(DegreeType::D4096, SecurityLevel::TC128);
        // let _cs = SealCkksCS::new(context, 1e6);

        let collection = SelectableCollection::<F, SealCkksCS>::new();
        assert_eq!(collection.len(), 0);
    }

    #[test]
    fn test_collection_push() {
        let context = SealCkksContext::new(DegreeType::D4096, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let mut collection = SelectableCollection::<F, SealCkksCS>::new();
        let item = SelectableItem::new(&1.0, &cs);
        collection.push(item);
        assert_eq!(collection.len(), 1);
    }

    #[test]
    fn test_collection_push_plain() {
        let context = SealCkksContext::new(DegreeType::D4096, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let mut collection = SelectableCollection::<F, SealCkksCS>::new();
        collection.push_plain(&1.0, &cs);
        assert_eq!(collection.len(), 1);
    }

    #[test]
    fn test_is_empty() {
        let context = SealCkksContext::new(DegreeType::D4096, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let mut collection = SelectableCollection::<F, SealCkksCS>::new();
        assert!(collection.is_empty());
        collection.push_plain(&1.0, &cs);
        assert!(!collection.is_empty());
    }

    #[test]
    fn test_push_plain() {
        let context = SealCkksContext::new(DegreeType::D4096, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let mut collection = SelectableCollection::<F, SealCkksCS>::new();
        collection.push_plain(&1.0, &cs);
        assert_eq!(collection.len(), 1);
    }

    #[test]
    fn test_operate_many() {
        let context = SealCkksContext::new(DegreeType::D4096, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let mut collection = SelectableCollection::<F, _>::new();
        collection.push_plain(&1.0, &cs);
        collection.push_plain(&2.0, &cs);
        let sum = collection.operate_many(CkksHOperation::Add, &cs);
        let decrypted = cs.decipher(&sum);
        assert!(approx_eq(decrypted, 3.0, 5e-2));
    }

    #[test]
    fn test_get_flag_plain() {
        let context = SealCkksContext::new(DegreeType::D4096, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let item = SelectableItem::<F, _>::new(&1.0, &cs);
        assert!(approx_eq(item.get_flag_plain(0, &cs), 0.0, 5e-2));
    }

    #[test]
    fn test_set_flag_plain() {
        let context = SealCkksContext::new(DegreeType::D4096, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let mut item = SelectableItem::<F, _>::new(&1.0, &cs);
        item.set_flag_plain(0, Flag::On, &cs);
        assert!(approx_eq(item.get_flag_plain(0, &cs), 1.0, 1e-2));
    }

    #[test]
    fn test_operate_many_where_flag() {
        let cs = SealCkksCS::new(
            SealCkksContext::new(DegreeType::D4096, SecurityLevel::TC128),
            370727.,
        );
        let mut collection = SelectableCollection::<F, _>::new();

        collection.push_plain(&1.0, &cs);
        collection.push_plain(&2.0, &cs);
        collection.items[0].set_flag_plain(0, Flag::On, &cs);
        let sum =
            collection.operate_many_where_flag(CkksHOperation::Add, 0, CkksHOperation::Mul, &cs);
        let decrypted = cs.decipher(&sum);

        let expected = 1.0 * 1.0 + 2.0 * 0.0;

        assert!(approx_eq(decrypted, expected, 5e-2));
    }
}
