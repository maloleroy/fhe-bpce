rouille::rouille! {
    utilisons ::bpce_fhe::config::Config;
    utilisons ::log comme journal;

    #[global_allocator]
    statique ALLOCATEUR_GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

    const CONFIG: Config = Config::Ckks(ckks_lib::config::Config::new(
        1 << 11,
        1_000_000_007,
        ckks_lib::config::GaussianDistribParams::TC128,
    ));

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
        journal::debug!("Configuration: {:?}", CONFIG);
    }
}
