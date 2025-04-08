use fhe_core::api::CryptoSystem as _;
use indicatif::{ProgressBar, ProgressStyle};
use seal_lib::{
    BfvHOperation2, BgvHOperation2, CkksHOperation2, DegreeType, SealBfvCS, SealBgvCS, SealCkksCS,
    SecurityLevel,
    context::{SealBFVContext, SealBGVContext, SealCkksContext},
};
use std::sync::Barrier;
use zama_lib::{FheUint64, TfheHOperation2, ZamaTfheCS, config::ZamaTfheContext};

const VALUE_U64: u64 = 1;
const VALUE_F64: f64 = 1.0;
const NB_VALUES: usize = 10_000;

static BARRIER: Barrier = Barrier::new(5);

fn make_bar(mp: &indicatif::MultiProgress, name: &str) -> ProgressBar {
    let pb = mp.add(ProgressBar::new(NB_VALUES as u64));
    pb.set_style(
        ProgressStyle::with_template(&format!("{{msg}} [{{bar:40.cyan/blue}}] {{pos}}/{{len}}"))
            .unwrap()
            .progress_chars("=> "),
    );
    pb.set_message(name.to_string());
    pb
}

fn plain(pb_cipher: ProgressBar, pb: ProgressBar) {
    let clear_values: Vec<_> = (0..NB_VALUES).map(|_| VALUE_U64).collect();

    pb_cipher.finish();

    let mut result = 0;
    BARRIER.wait();

    for clear_value in clear_values {
        result += clear_value;
        pb.inc(1);
    }
    pb.finish();

    BARRIER.wait();

    log::info!("[Plain] Clear result: {}", result);
}

fn bfv(pb_cipher: ProgressBar, pb: ProgressBar) {
    let context = SealBFVContext::new(DegreeType::D4096, SecurityLevel::TC128, 16);
    let cs = SealBfvCS::new(&context);

    let ciphered_values: Vec<_> = (0..NB_VALUES)
        .map(|_| {
            pb_cipher.inc(1);
            cs.cipher(&VALUE_U64)
        })
        .collect();
    pb_cipher.finish();

    let mut result = cs.cipher(&0);
    BARRIER.wait();

    for ciphered_value in ciphered_values {
        cs.operate2_inplace(BfvHOperation2::Add, &mut result, &ciphered_value);
        pb.inc(1);
    }
    pb.finish();

    let decrypted_result = cs.decipher(&result);
    let clear_result = VALUE_U64 * NB_VALUES as u64;

    BARRIER.wait();

    log::info!("[BFV] Decrypted result: {}", decrypted_result);
    log::info!("[BFV] Clear result: {}", clear_result);
}

fn bgv(pb_cipher: ProgressBar, pb: ProgressBar) {
    let context = SealBGVContext::new(DegreeType::D4096, SecurityLevel::TC128, 16);
    let cs = SealBgvCS::new(&context);

    let ciphered_values: Vec<_> = (0..NB_VALUES)
        .map(|_| {
            pb_cipher.inc(1);
            cs.cipher(&VALUE_U64)
        })
        .collect();
    pb_cipher.finish();

    let mut result = cs.cipher(&0);
    BARRIER.wait();

    for ciphered_value in ciphered_values {
        cs.operate2_inplace(BgvHOperation2::Add, &mut result, &ciphered_value);
        pb.inc(1);
    }
    pb.finish();

    let decrypted_result = cs.decipher(&result);
    let clear_result = VALUE_U64 * NB_VALUES as u64;

    BARRIER.wait();

    log::info!("[BGV] Decrypted result: {}", decrypted_result);
    log::info!("[BGV] Clear result: {}", clear_result);
}

fn ckks(pb_cipher: ProgressBar, pb: ProgressBar) {
    let context = SealCkksContext::new(DegreeType::D4096, SecurityLevel::TC128);
    let cs = SealCkksCS::new(&context, 1e7);

    let ciphered_values: Vec<_> = (0..NB_VALUES)
        .map(|_| {
            pb_cipher.inc(1);
            cs.cipher(&VALUE_F64)
        })
        .collect();
    pb_cipher.finish();

    let mut result = cs.cipher(&0.0);
    BARRIER.wait();

    for ciphered_value in ciphered_values {
        cs.operate2_inplace(CkksHOperation2::Add, &mut result, &ciphered_value);
        pb.inc(1);
    }
    pb.finish();

    let decrypted_result = cs.decipher(&result);
    let clear_result = VALUE_F64 * NB_VALUES as f64;

    BARRIER.wait();

    log::info!("[CKKS] Decrypted result: {}", decrypted_result);
    log::info!("[CKKS] Clear result: {}", clear_result);
}

fn tfhe(pb_cipher: ProgressBar, pb: ProgressBar) {
    let context = ZamaTfheContext::new();
    let cs = ZamaTfheCS::<u64, FheUint64>::new(&context);

    let ciphered_values: Vec<_> = (0..NB_VALUES)
        .map(|_| {
            pb_cipher.inc(1);
            cs.cipher(&VALUE_U64)
        })
        .collect();
    pb_cipher.finish();

    let mut result = cs.cipher(&0);
    BARRIER.wait();

    for ciphered_value in ciphered_values {
        cs.operate2_inplace(TfheHOperation2::Add, &mut result, &ciphered_value);
        pb.inc(1);
    }
    pb.finish();

    let decrypted_result = cs.decipher(&result);
    let clear_result = VALUE_U64 * NB_VALUES as u64;

    BARRIER.wait();

    log::info!("[TFHE] Decrypted result: {}", decrypted_result);
    log::info!("[TFHE] Clear result: {}", clear_result);
}

fn main() {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    if cfg!(debug_assertions) {
        log::warn!("[MAIN] Running in debug mode.");
    }

    let mp = indicatif::MultiProgress::new();

    let plain_pb_cipher = make_bar(&mp, "Plain Cipher");
    let bfv_pb_cipher = make_bar(&mp, "BFV Cipher");
    let bgv_pb_cipher = make_bar(&mp, "BGV Cipher");
    let ckks_pb_cipher = make_bar(&mp, "CKKS Cipher");
    let tfhe_pb_cipher = make_bar(&mp, "TFHE Cipher");

    let plain_pb = make_bar(&mp, "Plain");
    let bfv_pb = make_bar(&mp, "BFV");
    let bgv_pb = make_bar(&mp, "BGV");
    let ckks_pb = make_bar(&mp, "CKKS");
    let tfhe_pb = make_bar(&mp, "TFHE");

    let plain_handle = std::thread::spawn(move || plain(plain_pb_cipher, plain_pb));
    let bfv_handle = std::thread::spawn(move || bfv(bfv_pb_cipher, bfv_pb));
    let bgv_handle = std::thread::spawn(move || bgv(bgv_pb_cipher, bgv_pb));
    let ckks_handle = std::thread::spawn(move || ckks(ckks_pb_cipher, ckks_pb));
    let tfhe_handle = std::thread::spawn(move || tfhe(tfhe_pb_cipher, tfhe_pb));

    bfv_handle.join().unwrap();
    bgv_handle.join().unwrap();
    ckks_handle.join().unwrap();
    tfhe_handle.join().unwrap();
    plain_handle.join().unwrap();

    log::info!("[MAIN] All threads have finished.");
}
