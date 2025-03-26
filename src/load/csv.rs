//! Data stored in CSV format.

use bincode::Encode;
use csv::Reader;
use fhe_core::api::CryptoSystem;
use fhe_operations::single_ops::{SingleOpItem, SingleOpsData};
use seal_lib::BfvHOperation2; // Mock implementation tied to seal-lib (temporary)

const SIZE_LIMIT: u64 = 1024 * 1024;

pub struct CsvLoader<C: CryptoSystem> {
    phantom: std::marker::PhantomData<C>,
}

impl<C: CryptoSystem<Plaintext = u64, Operation2 = BfvHOperation2>> super::DataLoader<C>
    for CsvLoader<C>
where
    C::Operation2: Encode,
    C::Ciphertext: Encode,
{
    fn load(file: std::fs::File, cs: &C) -> super::DataResult<SingleOpsData<C>> {
        let mut rdr = Reader::from_reader(file);

        let mut items = SingleOpsData::new();

        for result in rdr.records() {
            let record = result.map_err(|_| super::DataError::Parsing)?;
            if record.len() != 3 {
                return Err(super::DataError::Parsing);
            }
            let lhs = record[0]
                .parse::<u64>()
                .map_err(|_| super::DataError::Parsing)?;
            let rhs = record[1]
                .parse::<u64>()
                .map_err(|_| super::DataError::Parsing)?;
            let op = match &record[2] {
                "+" => BfvHOperation2::Add,
                "*" => BfvHOperation2::Mul,
                _ => return Err(super::DataError::Parsing),
            };

            items.push(SingleOpItem::new(cs.cipher(&lhs), cs.cipher(&rhs), op));
        }

        Ok(items)
    }
}
