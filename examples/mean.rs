use ckks_lib::{
    cipher::{Decryptor, Encryptor},
    config::Config,
    key::generate_keys,
};
use core::sync::atomic::AtomicUsize;
use rand::{Rng, rng};

const MAX_VALUE: f64 = 100.0;
const AMOUNT: usize = 10_000_000;

/// Simulate reading from a stream (DB, ...)
fn fake_read() -> Option<f64> {
    static REMAINING: AtomicUsize = AtomicUsize::new(AMOUNT);

    let remaining = REMAINING.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    if remaining > 0 {
        Some(rng().random_range(0.0..MAX_VALUE))
    } else {
        None
    }
}

fn main() {
    let config = Config::new(4096, 100_000_000_007);
    let (pkey, skey) = generate_keys(config);

    let encryptor = Encryptor::new(pkey, config);
    let decryptor = Decryptor::new(skey, config);

    let mut mean_e = encryptor.encrypt(&[0.0], 1e7);

    while let Some(amount) = fake_read() {
        let ciphertext = encryptor.encrypt(&[amount], 1e7);
        mean_e = encryptor.homomorphic_add(&mean_e, &ciphertext);
    }

    mean_e = encryptor.homomorphic_div_plain(&mean_e, AMOUNT as f64);

    let decrypted = decryptor.decrypt(&mean_e)[0];

    println!("decrypted: {}", decrypted);
}
