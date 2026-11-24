mod config;
mod models;
mod nftables;
mod tracker;
mod processor;
mod engine;

use clap::Parser;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

use crate::config::FirewallConfig;
use crate::nftables::NftablesManager;
use crate::tracker::ConnectionTracker;
use crate::processor::PacketProcessor;
use crate::engine::FirewallEngine;

#[derive(Parser, Debug)]
#[command(author, version, about = "MTA:SA UDP/TCP Anti-Spoofing Firewall in Rust")]
struct Args {
    #[arg(long, default_value_t = 22003)]
    game_port: u16,

    #[arg(long, default_value_t = 22126)]
    server_list_port: u16,

    #[arg(long, default_value_t = 443)]
    tls_port: u16,

    #[arg(long, default_value_t = 45)]
    udp_min: u16,

    #[arg(long, default_value_t = 90)]
    udp_max: u16,

    #[arg(long, default_value_t = 100)]
    spam_threshold: u32,

    #[arg(long, default_value = "")]
    whitelist: String,

    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let log_level = if args.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(log_level))
        .init();

    tracing::info!("Starting MTA:SA Firewall...");

    let whitelist_ips: Vec<String> = args.whitelist
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let config = Arc::new(FirewallConfig {
        game_port: args.game_port,
        server_list_port: args.server_list_port,
        tls_port: args.tls_port,
        udp_join_length_min: args.udp_min,
        udp_join_length_max: args.udp_max,
        spam_threshold_packets: args.spam_threshold,
        whitelist_ips,
        ..Default::default()
    });

    let nft_manager = Arc::new(NftablesManager::new(config.clone()));
    if !nft_manager.setup() {
        tracing::error!("Failed to setup NFTables. Make sure you are running as root.");
        std::process::exit(1);
    }

    let tracker = Arc::new(ConnectionTracker::new(config.clone(), Some(nft_manager.clone())));
    
    // Start tracker cleanup task
    let tracker_clone = tracker.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            tracker_clone.cleanup_expired();
        }
    });

    let processor = Arc::new(PacketProcessor::new(config.clone(), tracker.clone()));
    let engine = FirewallEngine::new(config.clone(), tracker.clone(), processor.clone());

    engine.start();

    // Setup graceful shutdown
    tokio::signal::ctrl_c().await.unwrap();
    tracing::info!("Shutdown signal received...");
    nft_manager.cleanup();
    tracing::info!("Cleanup complete. Exiting.");
}
