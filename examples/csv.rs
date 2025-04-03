use csv::ReaderBuilder;
use fhe_core::api::CryptoSystem as _;
use rayon::prelude::*;
use seal_lib::{BfvHOperation2, SealBfvCS, context::SealBFVContext};

const BATCH_SIZE: usize = 1 << 15; // 32 KB

fn main() {
    let bfv_ctx = SealBFVContext::new(
        seal_lib::DegreeType::D4096,
        seal_lib::SecurityLevel::TC128,
        16,
    );
    let bfv_cs = SealBfvCS::new(&bfv_ctx);

    let file = std::fs::File::open("data.csv").unwrap();
    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(file);

    let headers = reader.headers().unwrap();
    let column_index = headers
        .iter()
        .position(|h| h == "rwa")
        .expect("Column 'rwa' not found");

    let records: Vec<_> = reader.records().map(|r| r.unwrap()).collect();

    let sum = records
        .par_chunks(BATCH_SIZE)
        .map(|batch| process_batch(batch, column_index, &bfv_cs))
        .reduce(
            || bfv_cs.cipher(&0),
            |mut acc, local_sum| {
                bfv_cs.operate2_inplace(BfvHOperation2::Add, &mut acc, &local_sum);
                acc
            },
        );

    let sum_d = bfv_cs.decipher(&sum);
    println!("Sum of all f64 of the column \"rwa\": {}", sum_d);
}

fn process_batch(
    batch: &[csv::StringRecord],
    column_index: usize,
    bfv_cs: &SealBfvCS,
) -> seal_lib::Ciphertext {
    let mut local_sum = bfv_cs.cipher(&0);

    for record in batch {
        let value: f64 = record[column_index]
            .parse()
            .expect("Failed to parse value as f64");
        let value_uint = (value * 100.0) as u64;
        let v_cipher = bfv_cs.cipher(&value_uint);
        bfv_cs.operate2_inplace(BfvHOperation2::Add, &mut local_sum, &v_cipher);
    }

    println!("Processed {} records.", batch.len());
    local_sum
}
