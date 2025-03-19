use criterion::{Criterion, criterion_group, criterion_main};
use fhe_core::api::CryptoSystem;
use seal_lib::{BfvHOperation, DegreeType, SealBfvCS, SecurityLevel, context::SealBFVContext};

fn benchmark_cipher(c: &mut Criterion) {
    let ctx = SealBFVContext::new(DegreeType::D2048, SecurityLevel::TC128, 16);
    let cipher = SealBfvCS::new(ctx);

    let input = 42_u64;

    c.bench_function("cipher", |b| {
        b.iter(|| {
            cipher.cipher(&input);
        })
    });

    let input2 = 42_u64;
    let ciphered_input = cipher.cipher(&input);
    let ciphered_input2 = cipher.cipher(&input2);

    c.bench_function("add", |b| {
        b.iter(|| {
            cipher.operate(BfvHOperation::Add, &ciphered_input, Some(&ciphered_input2));
        })
    });

    c.bench_function("mul", |b| {
        b.iter(|| {
            cipher.operate(BfvHOperation::Mul, &ciphered_input, Some(&ciphered_input2));
        })
    });

    c.bench_function("decipher", |b| {
        b.iter(|| {
            cipher.decipher(&ciphered_input);
        })
    });
}

criterion_group!(
    name = seal_lib_benchmarks;
    config = Criterion::default().measurement_time(core::time::Duration::from_secs(5));
    targets = benchmark_cipher
);
criterion_main!(seal_lib_benchmarks);
