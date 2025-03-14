use bpce_fhe::{Ciphertext, Context, Decryptor, Encryptor};
use seal_lib::{
    context::{CkksContext, Evaluator},
};

pub struct SelectableItem<const P: i64, const N: u32, const F: usize> {
    ciphertext: bpce_fhe::Ciphertext,
    flags: [Ciphertext; F],
}

impl<const P: i64, const N: u32, const F: usize> SelectableItem<P, N, F> {
    pub fn new(value: f64, encryptor: &Encryptor) -> Self {
        SelectableItem {
            ciphertext: encryptor.encrypt_f64(value),
            flags: core::array::from_fn(|_| encryptor.encrypt_f64(0.)),
        }
    }
}

pub struct SelectableCollection<const P: i64, const N: u32, const F: usize> {
    items: Vec<SelectableItem<P, N, F>>,
    context: Context,
    encryptor: bpce_fhe::Encryptor,
    evaluator: bpce_fhe::Evaluator,
    decryptor: bpce_fhe::Decryptor,
}

impl<const P: i64, const N: u32, const F: usize> SelectableCollection<P, N, F> {
    pub fn new(context: Context) -> Self {
        let seal_ctx = match &context {
            Context::Seal(seal_ctx) => seal_ctx,
            _ => panic!("Unexpected context type"),
        };
        let evaluator = context.evaluator();
        let encoder_e = seal_ctx.encoder(1e6);
        let encoder_d = seal_ctx.encoder(1e6);

        let (skey, pkey) = seal_ctx.generate_keys();
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

        SelectableCollection::<P, N, F> {
            items: Vec::new(),
            context,
            encryptor: enc,
            evaluator,
            decryptor: dec,
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn push(&mut self, item: SelectableItem<P, N, F>) {
        self.items.push(item);
    }

    pub fn push_plain(&mut self, item: f64) {
        self.items.push(SelectableItem::new(item, &self.encryptor));
    }

    pub fn sum(&self) -> Ciphertext {
        let mut sum = self.items[0].ciphertext.clone();
        for i in 1..self.items.len() {
            sum = self.evaluator.add(&sum, &self.items[i].ciphertext);
        }
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const P: i64 = 307;
    const N: u32 = 12;
    const F: usize = 2;

    #[test]
    fn test_new() {
        use bpce_fhe::ContextCreationParameters;
        use seal_lib::{DegreeType, SecurityLevel};
        let context = Context::new(ContextCreationParameters::SealCkks {
            pmod: DegreeType::D2048,
            cmod: DegreeType::D2048,
            sl: SecurityLevel::TC128,
        });
        let collection = SelectableCollection::<P, N, F>::new(context);
        assert_eq!(collection.len(), 0);
    }

    #[test]
    fn test_push() {
        use bpce_fhe::ContextCreationParameters;
        use seal_lib::{DegreeType, SecurityLevel};
        let context = Context::new(ContextCreationParameters::SealCkks {
            pmod: DegreeType::D2048,
            cmod: DegreeType::D2048,
            sl: SecurityLevel::TC128,
        });
        let mut collection = SelectableCollection::<P, N, F>::new(context);
        let item = SelectableItem::new(1.0, &collection.encryptor);
        collection.push(item);
        assert_eq!(collection.len(), 1);
    }

    #[test]
    fn test_push_plain() {
        use bpce_fhe::ContextCreationParameters;
        use seal_lib::{DegreeType, SecurityLevel};
        let context = Context::new(ContextCreationParameters::SealCkks {
            pmod: DegreeType::D2048,
            cmod: DegreeType::D2048,
            sl: SecurityLevel::TC128,
        });
        let mut collection = SelectableCollection::<P, N, F>::new(context);
        collection.push_plain(1.0);
        assert_eq!(collection.len(), 1);
    }

    #[test]
    fn test_sum() {
        use bpce_fhe::ContextCreationParameters;
        use seal_lib::{DegreeType, SecurityLevel};
        let context = Context::new(ContextCreationParameters::SealCkks {
            pmod: DegreeType::D2048,
            cmod: DegreeType::D2048,
            sl: SecurityLevel::TC128,
        });
        let mut collection = SelectableCollection::<P, N, F>::new(context);
        collection.push_plain(1.0);
        collection.push_plain(2.0);
        let sum = collection.sum();
        let decrypted = collection.decryptor.decrypt_f64(&sum);
        assert!((decrypted - 3.0).abs() < 1e-2);
    }
}
