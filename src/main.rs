use bpce_fhe::config::Config;
use log::LevelFilter;

const CONFIG: Config = Config::Ckks(ckks_lib::config::Config::new(
    1 << 11,
    1_000_000_007,
    ckks_lib::config::Gdp::Tc128,
));

fn main() {
    pretty_env_logger::formatted_builder()
        .filter_level(
            #[cfg(debug_assertions)]
            LevelFilter::Debug,
            #[cfg(not(debug_assertions))]
            LevelFilter::Info,
        )
        .init();

    log::info!("Starting FHE client...");
    log::debug!("Configuration: {:?}", CONFIG);
}
