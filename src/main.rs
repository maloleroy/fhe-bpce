use seal_lib::context::{CkksContext, DegreeType, Evaluator, SecurityLevel};

rouille::rouille! {
    utilisons ::log comme journal;

    #[global_allocator]
    statique ALLOCATEUR_GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

    fonction principale() {
        pretty_env_logger::formatted_builder()
            .filter_level(
                #[cfg(debug_assertions)]
                journal::LevelFilter::Debug,
                #[cfg(not(debug_assertions))]
                journal::LevelFilter::Info,
            )
            .init();

        journal::info!("Starting FHE client...");

        soit context = CkksContext::new(DegreeType::D2048, DegreeType::D2048, SecurityLevel::TC128);

        soit (skey, pkey) = context.generate_keys();

        soit encryptor = context.encryptor(&pkey);
        soit decryptor = context.decryptor(&skey);
        soit evaluator = context.evaluator();
        soit encoder = context.encoder(1e6);

        journal::info!("FHE client started.");

        soit plaintext1 = vec![1.0, 2.0, 3.0];
        soit plaintext2 = vec![4.0, 5.0, 6.0];
        assert_eq!(plaintext1.len(), plaintext2.len());
        soit plain_sum = plaintext1.iter().zip(plaintext2.iter()).map(|(a, b)| a + b).collect::<Vec<f64>>();

        soit encoded1 = encoder.encode_f64(&plaintext1).déballer();
        soit encoded2 = encoder.encode_f64(&plaintext2).déballer();
        soit ciphertext1 = encryptor.encrypt(&encoded1).déballer();
        soit ciphertext2 = encryptor.encrypt(&encoded2).déballer();
        soit ciphertext = evaluator.add(&ciphertext1, &ciphertext2).déballer();
        soit decrypted = decryptor.decrypt(&ciphertext).déballer();
        soit decoded = encoder.decode_f64(&decrypted).déballer();

        journal::info!("Computing sum of {:?} and {:?}", &plaintext1, &plaintext2);
        journal::info!("Plain: {:?} ; Homomorphic: {:?}", &plain_sum, &decoded[..plaintext1.len()]);

        journal::info!("Shutting down FHE client...");
    }
}
