use api::*;

struct SelectableItem<const P: i64, const N: u32, const F: usize> {
    ciphertext: Ciphertext<P, N>,
    flags: [Ciphertext<P, N>; F],
}

impl <const P: i64, const N: u32, const F: usize> SelectableItem<P, N, F> {
    pub fn from(value: f64) -> Self {
        SelectableItem {
            ciphertext: Ciphertext::from(value),
            flags: [Ciphertext::new(); F],
        }
    }
}

struct SelectableCollection<const P: i64, const N: u32, const F: usize> {
    items: Vec<SelectableItem<P, N, F>>,
    encryptor: Encryptor<P, N>,
    decryptor: Decryptor<P, N>
}

impl <const P: i64, const N: u32, const F: usize> SelectableCollection<P, N, F> {
    pub fn new() -> Self {
        SelectableCollection {
            items: Vec::new(),
            encryptor: Encryptor::new(),
            decryptor: Decryptor::new()
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn push(&mut self, item: SelectableItem<P, N, F>) {
        self.items.push(item);
    }

    pub fn push_plain(&mut self, item: f64) {
        let item = SelectableItem {
            ciphertext: Ciphertext::from(item),
            flags: [Ciphertext::new(); F],
        };
        self.items.push(item);
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
        let collection = SelectableCollection::<P, N, F>::new();
        assert_eq!(collection.len(), 0);
    }

    #[test]
    fn test_push() {
        let mut collection = SelectableCollection::<P, N, F>::new();
        let item = SelectableItem {
            ciphertext: Ciphertext::new(),
            flags: [Ciphertext::new(), Ciphertext::new()],
        };
        collection.push(item);
        assert_eq!(collection.len(), 1);
    }
}