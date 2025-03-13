use core::sync::atomic::{AtomicUsize, Ordering};
use rand::{Rng, rng};
use sealy::{
    CKKSEncoder, CKKSEncryptionParametersBuilder, CKKSEvaluator, CoefficientModulusFactory,
    Context, Decryptor, DegreeType, Encryptor, Evaluator, KeyGenerator, SecurityLevel,
};

const AMOUNT: usize = 2;
// Assert AMOUNT can be converted to f64 without loss of precision
const _: () = assert!(AMOUNT < 1 << 53);
const MAX_MONEY: f64 = 100.0;

fn fake_read() -> Option<f64> {
    static REMAINING: AtomicUsize = AtomicUsize::new(AMOUNT);
    let new = REMAINING.fetch_sub(1, Ordering::SeqCst);
    if new > 0 {
        Some(rng().random_range(0.0..MAX_MONEY))
    } else {
        None
    }
}

fn main() {
    let ctx = {
        let params = CKKSEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[60, 50, 60]).unwrap(),
            )
            .build()
            .unwrap();
        Context::new(&params, false, SecurityLevel::default()).unwrap()
    };
    let (secret_key, public_key) = {
        let key_gen = KeyGenerator::new(&ctx).unwrap();
        (key_gen.secret_key(), key_gen.create_public_key())
    };
    let encoder = CKKSEncoder::new(&ctx, 1e13).unwrap();
    let encryptor = Encryptor::with_public_key(&ctx, &public_key).unwrap();
    let decryptor = Decryptor::new(&ctx, &secret_key).unwrap();
    let evaluator = CKKSEvaluator::new(&ctx).unwrap();
    let mut moy_e = {
        let zero_encoded = encoder.encode_f64(&[0.0]).unwrap();
        encryptor.encrypt(&zero_encoded).unwrap()
    };
    while let Some(money) = fake_read() {
        let money_e = {
            let encoded = encoder.encode_f64(&[money]).unwrap();
            encryptor.encrypt(&encoded).unwrap()
        };
        evaluator.add_inplace(&mut moy_e, &money_e).unwrap();
    }
    let factor = 1.0 / AMOUNT as f64;
    evaluator
        .multiply_plain_inplace(&mut moy_e, &encoder.encode_f64(&[factor]).unwrap())
        .unwrap();
    let decrypted = decryptor.decrypt(&moy_e).unwrap();
    let decoded = encoder.decode_f64(&decrypted).unwrap();
    println!("{:?}", &decoded.into_iter().take(1).collect::<Vec<_>>());
}
