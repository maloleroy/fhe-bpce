use super::{unsized_data_recv, unsized_data_send};
use fhe_core::api::CryptoSystem;
use fhe_exchange::ExchangeData;
use seal_lib::{SealBfvCS, context::SealBFVContext};
use tokio::net::TcpStream;

pub async fn handle_client(mut stream: TcpStream) {
    let bfv_ctx = SealBFVContext::new(
        seal_lib::DegreeType::D4096,
        seal_lib::SecurityLevel::TC128,
        16,
    );
    let bfv_cs = SealBfvCS::new(&bfv_ctx);

    let data = unsized_data_recv(&mut stream).await;

    let Ok(exch_data) =
        bincode::decode_from_slice_with_context(&data, super::BINCODE_CONFIG, bfv_ctx)
    else {
        log::error!("Failed to decode data from client");
        return;
    };

    let exch_data: ExchangeData<SealBfvCS> = exch_data.0;

    log::info!("Operating on {} data pairs", exch_data.len());

    let mut results = Vec::new();
    for (lhs, rhs, op) in exch_data.iter_over_data() {
        results.push(bfv_cs.operate(*op, lhs, rhs));
    }

    let bytes = bincode::encode_to_vec(results, super::BINCODE_CONFIG).unwrap();

    log::info!("Sending data back to client");

    unsized_data_send(bytes, &mut stream).await;
}
