use arrow::array::Float64Array;
use fhe_core::api::CryptoSystem as _;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use rayon::iter::{ParallelBridge, ParallelIterator};
use seal_lib::{BfvHOperation2, SealBfvCS, context::SealBFVContext};
use std::sync::Mutex;

const BATCH_SIZE: usize = 1 << 15; // 32 KB

fn main() {
    let bfv_ctx = SealBFVContext::new(
        seal_lib::DegreeType::D4096,
        seal_lib::SecurityLevel::TC128,
        16,
    );
    let bfv_cs = SealBfvCS::new(&bfv_ctx);

    let file = std::fs::File::open("data.parquet").unwrap();
    let parquet_reader = ParquetRecordBatchReaderBuilder::try_new(file)
        .unwrap()
        .with_batch_size(BATCH_SIZE) // 32 KB
        .build()
        .unwrap();

    let iter = parquet_reader.into_iter();

    let sum = Mutex::new(bfv_cs.cipher(&0));

    iter.par_bridge().for_each(|batch| {
        let batch = batch.unwrap();

        let column_index = batch
            .schema()
            .fields()
            .iter()
            .position(|f| f.name() == "rwa")
            .expect("Column 'rwa' not found");

        let column = batch.column(column_index);
        let array = column
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("Column is not Float64Array");

        let mut local_sum = bfv_cs.cipher(&0);

        for i in 0..array.len() {
            let value = array.value(i);
            let value_uint = (value * 100.0) as u64;
            let v_cipher = bfv_cs.cipher(&value_uint);
            bfv_cs.operate2_inplace(BfvHOperation2::Add, &mut local_sum, &v_cipher);
        }

        println!("Summed {} f64 of the column \"rwa\".", BATCH_SIZE);

        let mut sum_lock = sum.lock().unwrap();
        bfv_cs.operate2_inplace(BfvHOperation2::Add, &mut sum_lock, &local_sum);
    });

    let sum_d = bfv_cs.decipher(&sum.lock().unwrap());
    println!("Sum of all f64 of the column \"rwa\": {}", sum_d);
}
