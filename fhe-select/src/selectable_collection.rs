use fhe_core::api::CryptoSystem;

pub const FLAG_ON: f64 = 1.0;

pub const FLAG_OFF: f64 = 0.0;

pub struct SelectableItem<const F: usize, C: CryptoSystem> {
    ciphertext: C::Ciphertext,
    flags: [C::Ciphertext; F],
}

impl<const F: usize, C: CryptoSystem<Plaintext = f64, Ciphertext: Clone>> SelectableItem<F, C> {
    pub fn new(value: &C::Plaintext, cs: &C) -> Self {
        const DEFAULT_FLAG: f64 = FLAG_OFF;
        Self {
            ciphertext: cs.cipher(value),
            flags: core::array::from_fn(|_| cs.cipher(&DEFAULT_FLAG)),
        }
    }

    pub fn get_flag(&self, index: usize) -> Option<&C::Ciphertext> {
        self.flags.get(index)
    }

    pub fn get_flag_plain(&self, index: usize, cs: &C) -> f64 {
        cs.decipher(&self.flags[index])
    }

    pub fn set_flag_plain(&mut self, index: usize, value: f64, cs: &C) {
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

    pub fn operate_many_where_flag(
        &self,
        op: C::Operation,
        flag_index: usize,
        select_op: C::Operation,
    ) -> C::Ciphertext
    where
        C::Operation: Copy,
    {
        assert!(!self.items.is_empty());

        let first_item = &self.items[0];
        let first_flag = first_item.get_flag(flag_index);
        let mut sum: C::Ciphertext = self
            .cs
            .operate(select_op, &first_item.ciphertext, first_flag);

        for item in self.items.iter().skip(1) {
            let flag = item.get_flag(flag_index);
            let product = self.cs.operate(select_op, &item.ciphertext, flag);
            sum = self.cs.operate(op, &sum, Some(&product)).clone();
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

        let collection = SelectableCollection::<F, _>::new(cs);
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
    fn test_operate_many() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let mut collection = SelectableCollection::<F, SealCkksCS>::new(cs);
        collection.push_plain(1.0);
        collection.push_plain(2.0);
        let sum = collection.operate_many(CkksHOperation::Add);
        let decrypted = collection.cs.decipher(&sum);
        assert!(approx_eq(decrypted, 3.0, 5e-2));
    }

    #[test]
    fn test_get_flag_plain() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let item = SelectableItem::<F, _>::new(&1.0, &cs);
        assert!(approx_eq(item.get_flag_plain(0, &cs), 0.0, 5e-2));
    }

    #[test]
    fn test_set_flag_plain() {
        let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
        let cs = SealCkksCS::new(context, 1e6);
        let mut item = SelectableItem::<F, _>::new(&1.0, &cs);
        item.set_flag_plain(0, 1.0, &cs);
        assert!(approx_eq(item.get_flag_plain(0, &cs), 1.0, 1e-2));
    }

    #[test]
    fn test_operate_many_where_flag() {
        let mut collection = SelectableCollection::<F, SealCkksCS>::new(SealCkksCS::new(
            SealCkksContext::new(DegreeType::D4096, SecurityLevel::TC128),
            370727.,
        ));

        collection.push_plain(1.0);
        collection.push_plain(2.0);
        collection.items[0].set_flag_plain(0, FLAG_ON, &collection.cs);
        let sum = collection.operate_many_where_flag(CkksHOperation::Add, 0, CkksHOperation::Mul);
        let decrypted = collection.cs.decipher(&sum);

        let expected = 1.0 * 1.0 + 2.0 * 0.0;

        assert!(approx_eq(decrypted, expected, 5e-2));
    }
}
