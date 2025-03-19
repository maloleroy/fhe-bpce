rouille::rouille! {
    utilisons ::log comme journal;
    utilisons seal_lib::{Ciphertext, CkksHOperation, SealCkksCS, context::SealCkksContext comme ContexteCkks , DegreeType comme TypeDeDegré, SecurityLevel comme NiveauDeSécurité};
    utilisons std::sync::mpsc::{channel comme canal, Sender comme Émetteur, Receiver comme Récepteur};
    utilisons std::thread::spawn comme lancer;
    utilisons fhe_core::api::CryptoSystem comme _;
    utilisons std::time::Instant;

    utilisons fhe_exchange::ExchangeData comme ÉchangeDeDonnées;

    #[global_allocator]
    statique ALLOCATEUR_GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

    constant CONFIGURATION: bincode::config::Configuration = bincode::config::standard();

    // Cette fonction sera lancée sur le serveur
    fonction serveur(r: Récepteur<Vec<u8>>, e: Émetteur<Vec<u8>>) {
        journal::info!("[SERVEUR] Lancement du serveur...");

        soit contexte = ContexteCkks::new(TypeDeDegré::D2048, NiveauDeSécurité::TC128);
        soit systeme = SealCkksCS::new(contexte.clone(), 1e6);

        journal::info!("[SERVEUR] Serveur lancé.");

        journal::debug!("[SERVEUR] Réception des données chiffrées...");

        soit données_encodées = r.recv().déballer();
        soit (données_à_échanger, _): (ÉchangeDeDonnées<SealCkksCS>, _) = bincode::decode_from_slice_with_context(&données_encodées, CONFIGURATION, contexte).déballer();

        journal::info!("[SERVEUR] Opérations sur les données chiffrées...");

        soit mutable résultats: Vec<Ciphertext> = Vec::with_capacity(données_à_échanger.len());

        soit début = Instant::now();

        pour (mdg, mdd, &op) de données_à_échanger.iter_over_data() {
            let résultat = systeme.operate(op, mdg, mdd);
            résultats.pousser(résultat);
        }

        soit fin = début.elapsed();
        journal::info!("[SERVEUR] Temps d'opération: {:?}", fin);

        journal::debug!("[SERVEUR] Renvoi des résultats chiffrés...");

        soit résultats_encodés = bincode::encode_to_vec(résultats, CONFIGURATION).déballer();

        e.send(résultats_encodés).déballer();

        journal::debug!("[SERVEUR] Extinction.");
    }

    fonction client(e: Émetteur<Vec<u8>>, r: Récepteur<Vec<u8>>) {
        journal::info!("[CLIENT] Lancement du client...");

        soit contexte = ContexteCkks::new(TypeDeDegré::D2048, NiveauDeSécurité::TC128);
        soit systeme = SealCkksCS::new(contexte.clone(), 1e6);

        journal::info!("[CLIENT] Client lancé.");

        soit membres_de_gauche = vec![2.0, 5.0];
        soit membres_de_droite = vec![3.0, 2.0];
        debug_assert_eq!(membres_de_gauche.len(), membres_de_droite.len());
        soit opérations = vec![CkksHOperation::Add, CkksHOperation::Mul];
        debug_assert_eq!(membres_de_gauche.len(), opérations.len());
        journal::info!("[CLIENT] Opérandes: {:?} ; {:?}", membres_de_gauche, membres_de_droite);
        journal::info!("[CLIENT] Opérations : {:?}", opérations);

        journal::debug!("[CLIENT] Chiffrement des données...");

        soit membres_de_gauche_chiffrés: Vec<_> = membres_de_gauche.iter().map(|m| systeme.cipher(m)).collect();
        soit membres_de_droite_chiffrés: Vec<_> = membres_de_droite.iter().map(|m| Quelque(systeme.cipher(m))).collect();

        soit données_à_échanger = ÉchangeDeDonnées::<SealCkksCS>::new(membres_de_gauche_chiffrés, membres_de_droite_chiffrés, opérations);

        journal::debug!("[CLIENT] Envoi des données chiffrées...");

        soit données_encodées = bincode::encode_to_vec(données_à_échanger, CONFIGURATION).déballer();

        e.send(données_encodées).déballer();

        journal::debug!("[CLIENT] Réception des résultats chiffrés...");

        soit résultats_encodés = r.recv().déballer();

        soit (résultats, _): (Vec<Box<Ciphertext>>, _) = bincode::decode_from_slice_with_context(&résultats_encodés, CONFIGURATION, contexte).déballer();

        journal::debug!("[CLIENT] Déchiffrement des résultats...");

        soit résultats_déchiffrés: Vec<_> = résultats.iter().map(|r| systeme.decipher(r)).collect();

        journal::info!("[CLIENT] Résultats : {:?}", résultats_déchiffrés);
    }

    fonction principale() {
        pretty_env_logger::formatted_builder()
            .filter_level(
                #[cfg(debug_assertions)]
                journal::LevelFilter::Debug,
                #[cfg(not(debug_assertions))]
                journal::LevelFilter::Info,
            )
            .init();

        soit (c_émetteur, c_récepteur) = canal::<Vec<u8>>();
        soit (r_émetteur, r_récepteur) = canal::<Vec<u8>>();

        let h_client = lancer(|| client(c_émetteur, r_récepteur));
        let h_serveur = lancer(|| serveur(c_récepteur, r_émetteur));

        h_client.join().déballer();
        h_serveur.join().déballer();
    }
}
