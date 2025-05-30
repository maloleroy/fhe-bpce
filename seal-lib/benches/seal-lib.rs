use criterion::{Criterion, criterion_group, criterion_main};
use fhe_core::api::CryptoSystem;
use seal_lib::{
    BfvHOperation2, BgvHOperation2, CkksHOperation2, DegreeType, SealBfvCS, SealBgvCS, SealCkksCS,
    SecurityLevel,
    context::{SealBFVContext, SealBGVContext, SealCkksContext},
};

fn benchmark_bfv(c: &mut Criterion) {
    let ctx = SealBFVContext::new(DegreeType::D2048, SecurityLevel::TC128, 16);
    let cipher = SealBfvCS::new(&ctx);

    let input = 42_u64;

    c.bench_function("bfv cipher", |b| {
        b.iter(|| {
            cipher.cipher(&input);
        })
    });

    let input2 = 42_u64;
    let ciphered_input = cipher.cipher(&input);
    let ciphered_input2 = cipher.cipher(&input2);

    c.bench_function("bfv add", |b| {
        b.iter(|| {
            let _ = cipher.operate2(BfvHOperation2::Add, &ciphered_input, &ciphered_input2);
        })
    });

    c.bench_function("bfv mul", |b| {
        b.iter(|| {
            let _ = cipher.operate2(BfvHOperation2::Mul, &ciphered_input, &ciphered_input2);
        })
    });

    c.bench_function("bfv decipher", |b| {
        b.iter(|| {
            cipher.decipher(&ciphered_input);
        })
    });
}

fn benchmark_bgv(c: &mut Criterion) {
    let ctx = SealBGVContext::new(DegreeType::D2048, SecurityLevel::TC128, 16);
    let cipher = SealBgvCS::new(&ctx);

    let input = 42_u64;

    c.bench_function("bgv cipher", |b| {
        b.iter(|| {
            cipher.cipher(&input);
        })
    });

    let input2 = 42_u64;
    let ciphered_input = cipher.cipher(&input);
    let ciphered_input2 = cipher.cipher(&input2);

    c.bench_function("bgv add", |b| {
        b.iter(|| {
            let _ = cipher.operate2(BgvHOperation2::Add, &ciphered_input, &ciphered_input2);
        })
    });

    c.bench_function("bgv mul", |b| {
        b.iter(|| {
            let _ = cipher.operate2(BgvHOperation2::Mul, &ciphered_input, &ciphered_input2);
        })
    });

    c.bench_function("bgv decipher", |b| {
        b.iter(|| {
            cipher.decipher(&ciphered_input);
        })
    });
}

fn benchmark_ckks(c: &mut Criterion) {
    let ctx = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
    let cipher = SealCkksCS::new(&ctx, 1e6);

    let input = 42.0_f64;

    c.bench_function("ckks cipher", |b| {
        b.iter(|| {
            cipher.cipher(&input);
        })
    });

    let input2 = 42.0_f64;
    let ciphered_input = cipher.cipher(&input);
    let ciphered_input2 = cipher.cipher(&input2);

    c.bench_function("ckks add", |b| {
        b.iter(|| {
            let _ = cipher.operate2(CkksHOperation2::Add, &ciphered_input, &ciphered_input2);
        })
    });

    c.bench_function("ckks mul", |b| {
        b.iter(|| {
            let _ = cipher.operate2(CkksHOperation2::Mul, &ciphered_input, &ciphered_input2);
        })
    });

    c.bench_function("ckks decipher", |b| {
        b.iter(|| {
            cipher.decipher(&ciphered_input);
        })
    });
}

criterion_group!(
    name = seal_lib_benchmarks;
    config = Criterion::default().measurement_time(core::time::Duration::from_secs(5));
    targets = benchmark_bfv,benchmark_bgv,benchmark_ckks
);
criterion_main!(seal_lib_benchmarks);
