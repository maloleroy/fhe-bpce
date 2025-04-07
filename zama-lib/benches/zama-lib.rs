use criterion::{Criterion, criterion_group, criterion_main};
use fhe_core::api::CryptoSystem;
use zama_lib::{FheUint32, TfheHOperation2, ZamaTfheCS, config::ZamaTfheContext};

fn benchmark_tfhe(c: &mut Criterion) {
    let ctx = ZamaTfheContext::new();
    let cipher = ZamaTfheCS::<u32, FheUint32>::new(&ctx);

    let input = 42;

    c.bench_function("tfhe cipher", |b| {
        b.iter(|| {
            cipher.cipher(&input);
        })
    });

    let input2 = 42;
    let ciphered_input = cipher.cipher(&input);
    let ciphered_input2 = cipher.cipher(&input2);

    c.bench_function("tfhe add", |b| {
        b.iter(|| {
            let _ = cipher.operate2(TfheHOperation2::Add, &ciphered_input, &ciphered_input2);
        })
    });

    c.bench_function("tfhe mul", |b| {
        b.iter(|| {
            let _ = cipher.operate2(TfheHOperation2::Mul, &ciphered_input, &ciphered_input2);
        })
    });

    c.bench_function("tfhe decipher", |b| {
        b.iter(|| {
            cipher.decipher(&ciphered_input);
        })
    });
}

criterion_group!(
    name = zama_lib_benchmarks;
    config = Criterion::default().measurement_time(core::time::Duration::from_secs(5));
    targets = benchmark_tfhe
);
criterion_main!(zama_lib_benchmarks);
