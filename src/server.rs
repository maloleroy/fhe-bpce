use super::{unsized_data_recv, unsized_data_send};
use fhe_core::api::CryptoSystem;
use fhe_exchange::ExchangeData;
use rayon::prelude::*;
use seal_lib::{SealBfvCS, context::SealBFVContext};
use tokio::net::TcpStream;

pub async fn handle_client(mut stream: TcpStream) {
    let bfv_ctx = SealBFVContext::new(
        seal_lib::DegreeType::D4096,
        seal_lib::SecurityLevel::TC128,
        16,
    );
    let bfv_cs = SealBfvCS::new(&bfv_ctx);

    let Ok(data) = unsized_data_recv(&mut stream).await else {
        log::error!("Failed to receive data from client");
        return;
    };

    let Ok(exch_data) =
        bincode::decode_from_slice_with_context(&data, super::BINCODE_CONFIG, bfv_ctx)
    else {
        log::error!("Failed to decode data from client");
        return;
    };

    let exch_data: ExchangeData<SealBfvCS> = exch_data.0;

    log::info!(
        "Operating on {} data pairs with {} threads",
        exch_data.len(),
        rayon::current_num_threads()
    );

    let start = std::time::Instant::now();

    let results = exch_data
        .iter_over_data()
        .par_bridge()
        .map(|(lhs, rhs, &op)| bfv_cs.operate(op, lhs, rhs))
        .collect::<Vec<_>>();

    log::info!("Data processed in {:?}", start.elapsed());

    let bytes = bincode::encode_to_vec(results, super::BINCODE_CONFIG).unwrap();

    log::info!("Sending data back to client");

    let send_res = unsized_data_send(bytes, &mut stream).await;

    if let Err(e) = send_res {
        log::error!("Failed to send data back to client: {e}");
    }
}
