use log::LevelFilter;
use pretty_env_logger;

fn main() {
    pretty_env_logger::formatted_builder()
        .filter_level(LevelFilter::Debug)
        .init();

    log::info!("Starting FHE client...");
}
