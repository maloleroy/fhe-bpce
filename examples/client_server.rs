use fhe_core::api::CryptoSystem as _;
use fhe_operations::seq_ops::{SeqOpItem, SeqOpsData};
use seal_lib::{
    Ciphertext, CkksHOperation2, DegreeType, SealCkksCS, SecurityLevel, context::SealCkksContext,
};
use std::sync::mpsc::{Receiver, Sender, channel};

#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

const CONFIGURATION: bincode::config::Configuration = bincode::config::standard();

fn server(r: Receiver<Vec<u8>>, e: Sender<Vec<u8>>) {
    log::info!("[SERVEUR] Lancement du serveur...");

    let context = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
    let cs = SealCkksCS::new(&context, 1e7);

    log::info!("[SERVEUR] Serveur lancé.");

    log::debug!("[SERVEUR] Réception des données chiffrées...");

    let encoded_data = r.recv().unwrap();
    let (data, _): (SeqOpsData<SealCkksCS>, _) =
        bincode::decode_from_slice_with_context(&encoded_data, CONFIGURATION, context).unwrap();

    log::info!("[SERVEUR] Opérations sur les données chiffrées...");

    let mut results: Vec<Ciphertext> = Vec::with_capacity(data.len());

    let start = std::time::Instant::now();

    for item in data.iter_over_data() {
        results.push(item.execute(&cs));
    }

    let end = start.elapsed();
    log::info!("[SERVEUR] Temps d'opération: {:?}", end);

    log::debug!("[SERVEUR] Renvoi des résultats chiffrés...");

    let reencoded_results = bincode::encode_to_vec(results, CONFIGURATION).unwrap();

    e.send(reencoded_results).unwrap();

    log::debug!("[SERVEUR] Extinction.");
}

fn client(e: Sender<Vec<u8>>, r: Receiver<Vec<u8>>) {
    log::info!("[CLIENT] Lancement du client...");

    let contexte = SealCkksContext::new(DegreeType::D2048, SecurityLevel::TC128);
    let systeme = SealCkksCS::new(&contexte, 1e7);

    log::info!("[CLIENT] Client lancé.");

    let mut données_à_échanger = SeqOpsData::<SealCkksCS>::new();

    let op1 = SeqOpItem::new(
        systeme.cipher(&2.0),
        systeme.cipher(&3.0),
        CkksHOperation2::Add,
    );
    let op2 = SeqOpItem::new(
        systeme.cipher(&5.0),
        systeme.cipher(&2.0),
        CkksHOperation2::Mul,
    );
    données_à_échanger.push(op1);
    données_à_échanger.push(op2);
    log::info!("[CLIENT] Opérations: 2.0 + 3.0 ; 5.0 * 2.0");

    log::debug!("[CLIENT] Chiffrement des données...");
    log::debug!("[CLIENT] Envoi des données chiffrées...");

    let données_encodées = bincode::encode_to_vec(données_à_échanger, CONFIGURATION).unwrap();

    e.send(données_encodées).unwrap();

    log::debug!("[CLIENT] Réception des résultats chiffrés...");

    let résultats_encodés = r.recv().unwrap();

    let (résultats, _): (Vec<Box<Ciphertext>>, _) =
        bincode::decode_from_slice_with_context(&résultats_encodés, CONFIGURATION, contexte)
            .unwrap();

    log::debug!("[CLIENT] Déchiffrement des résultats...");

    let résultats_déchiffrés: Vec<_> = résultats.iter().map(|r| systeme.decipher(r)).collect();

    log::info!("[CLIENT] Résultats : {:?}", résultats_déchiffrés);
}

fn main() {
    pretty_env_logger::formatted_builder()
        .filter_level(
            #[cfg(debug_assertions)]
            log::LevelFilter::Debug,
            #[cfg(not(debug_assertions))]
            log::LevelFilter::Info,
        )
        .init();

    let (c_émetteur, c_récepteur) = channel::<Vec<u8>>();
    let (r_émetteur, r_récepteur) = channel::<Vec<u8>>();

    let h_client = std::thread::spawn(|| client(c_émetteur, r_récepteur));
    let h_serveur = std::thread::spawn(|| server(c_récepteur, r_émetteur));

    h_client.join().unwrap();
    h_serveur.join().unwrap();
}
