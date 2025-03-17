use fhe_core::api::CryptoSystem;
use seal_lib::CkksHOperation;

pub struct SelectableItem<const F: usize, C: CryptoSystem> {
    ciphertext: C::Ciphertext,
    flags: [C::Ciphertext; F],
}

impl<const F: usize, C: CryptoSystem<Plaintext = f64>> SelectableItem<F, C> {
    pub fn new(value: &C::Plaintext, cs: &C) -> Self {
        SelectableItem {
            ciphertext: cs.cipher(value),
            flags: core::array::from_fn(|_| cs.cipher(&0.0)),
        }
    }
}

pub struct SelectableCollection<const F: usize, C: CryptoSystem> {
    items: Vec<SelectableItem<F, C>>,
    cs: C,
}

impl<
    const F: usize,
    C: CryptoSystem<Plaintext = f64, Operation = CkksHOperation, Ciphertext: Clone>,
> SelectableCollection<F, C>
{
    pub fn new(cs: C) -> Self {
        SelectableCollection::<F, C> {
            items: Vec::new(),
            cs,
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn push(&mut self, item: SelectableItem<F, C>) {
        self.items.push(item);
    }

    pub fn push_plain(&mut self, item: f64) {
        self.items.push(SelectableItem::new(&item, &self.cs));
    }

    pub fn sum(&self) -> C::Ciphertext {
        let mut sum: C::Ciphertext = self.items[0].ciphertext.clone();
        for i in 1..self.items.len() {
            sum = self
                .cs
                .operate(CkksHOperation::Add, &sum, Some(&self.items[i].ciphertext))
                .clone();
        }
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_lib::{DegreeType, SealCkksCS, SecurityLevel, context::SealCkksContext};
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
        let sum = collection.sum();
        let decrypted = collection.cs.decipher(&sum);
        assert!((decrypted - 3.0).abs() < 1e-2);
    }
}
