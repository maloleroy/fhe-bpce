//! Data stored in CSV format.

use bincode::Encode;
use csv::Reader;
use fhe_core::api::CryptoSystem;
use fhe_exchange::ExchangeData;
use seal_lib::BfvHOperation; // Mock implementation tied to seal-lib (temporary)

const SIZE_LIMIT: u64 = 1024 * 1024;

pub struct CsvLoader<C: CryptoSystem> {
    phantom: std::marker::PhantomData<C>,
}

impl<C: CryptoSystem<Plaintext = u64, Operation = BfvHOperation>> super::DataLoader<C>
    for CsvLoader<C>
where
    C::Operation: Encode,
    C::Ciphertext: Encode,
{
    fn load(file: std::fs::File, cs: &C) -> super::DataResult<ExchangeData<C>> {
        let mut rdr = Reader::from_reader(file);

        let mut lhss = Vec::new();
        let mut rhss = Vec::new();
        let mut ops = Vec::new();

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
                "+" => BfvHOperation::Add,
                "*" => BfvHOperation::Mul,
                _ => return Err(super::DataError::Parsing),
            };
            lhss.push(cs.cipher(&lhs));
            rhss.push(Some(cs.cipher(&rhs)));
            ops.push(op);
        }

        let exchange_data = ExchangeData::new(lhss, rhss, ops);

        Ok(exchange_data)
    }
}
