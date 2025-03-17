use fhe_core::api::CryptoSystem;

pub struct SelectableItem<const F: usize, C: CryptoSystem> {
    ciphertext: C::Ciphertext,
    flags: [C::Ciphertext; F],
}

impl<const F: usize, C: CryptoSystem<Plaintext = f64>> SelectableItem<F, C> {
    pub fn new(value: &C::Plaintext, cs: &C) -> Self {
        Self {
            ciphertext: cs.cipher(value),
            flags: core::array::from_fn(|_| cs.cipher(&0.0)),
        }
    }

    pub fn get_flag(&self, index: usize, cs: &C) -> f64 {
        cs.decipher(&self.flags[index])
    }

    pub fn set_flag(&mut self, index: usize, value: f64, cs: &C) {
        self.flags[index] = cs.cipher(&value);
    }
}

pub struct SelectableCollection<const F: usize, C: CryptoSystem> {
    items: Vec<SelectableItem<F, C>>,
    cs: C,
}

impl<const F: usize, C: CryptoSystem<Plaintext = f64, Ciphertext: Clone>>
    SelectableCollection<F, C>
{
    pub const fn new(cs: C) -> Self {
        Self {
            items: Vec::new(),
            cs,
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn push(&mut self, item: SelectableItem<F, C>) {
        self.items.push(item);
    }

    pub fn push_plain(&mut self, item: f64) {
        self.items.push(SelectableItem::new(&item, &self.cs));
    }

    pub fn operate_many(&self, op: C::Operation) -> C::Ciphertext
    where
        C::Operation: Copy,
    {
        let mut sum: C::Ciphertext = self.items[0].ciphertext.clone();
        for i in 1..self.items.len() {
            sum = self
                .cs
                .operate(op, &sum, Some(&self.items[i].ciphertext))
                .clone();
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
    fn test_new() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);

        let collection = SelectableCollection::<F, SealCkksCS>::new(cs);
        assert_eq!(collection.len(), 0);
    }

    #[test]
    fn test_push() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let mut collection = SelectableCollection::<F, SealCkksCS>::new(cs);
        let item = SelectableItem::new(&1.0, &collection.cs);
        collection.push(item);
        assert_eq!(collection.len(), 1);
    }

    #[test]
    fn test_push_plain() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let mut collection = SelectableCollection::<F, SealCkksCS>::new(cs);
        collection.push_plain(1.0);
        assert_eq!(collection.len(), 1);
    }

    #[test]
    fn test_sum() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let mut collection = SelectableCollection::<F, SealCkksCS>::new(cs);
        collection.push_plain(1.0);
        collection.push_plain(2.0);
        let sum = collection.operate_many(CkksHOperation::Add);
        let decrypted = collection.cs.decipher(&sum);
        assert!(approx_eq(decrypted, 3.0, 1e-2));
    }

    #[test]
    fn test_get_flag() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let item = SelectableItem::<F, _>::new(&1.0, &cs);
        assert!(approx_eq(item.get_flag(0, &cs), 0.0, 1e-2));
    }

    #[test]
    fn test_set_flag() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let mut item = SelectableItem::<F, _>::new(&1.0, &cs);
        item.set_flag(0, 1.0, &cs);
        assert!(approx_eq(item.get_flag(0, &cs), 1.0, 1e-2));
    }
}
