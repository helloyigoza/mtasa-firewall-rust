use std::process::Command;
use std::sync::Arc;
use crate::config::FirewallConfig;

pub struct NftablesManager {
    config: Arc<FirewallConfig>,
}

impl NftablesManager {
    const TABLE_NAME: &'static str = "mta_firewall";
    const CHAIN_NAME: &'static str = "input";
    const SET_NAME: &'static str = "mta_verified";

    pub fn new(config: Arc<FirewallConfig>) -> Self {
        Self { config }
    }

    fn run_cmd(cmd: &str, ignore_error: bool) -> bool {
        match Command::new("sh").arg("-c").arg(cmd).output() {
            Ok(output) => {
                if !output.status.success() && !ignore_error {
                    tracing::error!("Command failed: {}\n{}", cmd, String::from_utf8_lossy(&output.stderr));
                    false
                } else {
                    true
                }
            }
            Err(e) => {
                if !ignore_error {
                    tracing::error!("Command error: {}", e);
                }
                false
            }
        }
    }

    pub fn setup(&self) -> bool {
        // Delete old table if exists
        Self::run_cmd(&format!("nft delete table ip {}", Self::TABLE_NAME), true);

        // Create table
        if !Self::run_cmd(&format!("nft add table ip {}", Self::TABLE_NAME), false) { return false; }

        // Create Set (for Whitelist)
        let set_cmd = format!("nft add set ip {} {} '{{ type ipv4_addr; flags timeout; }}'", Self::TABLE_NAME, Self::SET_NAME);
        if !Self::run_cmd(&set_cmd, false) { return false; }

        // Create Chain
        let chain_cmd = format!("nft add chain ip {} {} '{{ type filter hook input priority -150; }}'", Self::TABLE_NAME, Self::CHAIN_NAME);
        if !Self::run_cmd(&chain_cmd, false) { return false; }

        // UDP Traffic Strategy
        // Server List Port (22126)
        let start_q = self.config.udp_queue_start;
        let end_q = start_q + self.config.udp_queue_count - 1;
        let limit_queue_spec = if self.config.udp_queue_count > 1 {
            format!("num {}-{} fanout", start_q, end_q)
        } else {
            format!("num {}", start_q)
        };

        let rule1 = format!(
            "nft add rule ip {} {} udp dport {} limit rate {}/second burst 100 packets queue {}",
            Self::TABLE_NAME, Self::CHAIN_NAME, self.config.server_list_port, self.config.spam_threshold_packets, limit_queue_spec
        );
        Self::run_cmd(&rule1, false);

        // Game Port (22003) - strict TCP first policy
        let rule2 = format!(
            "nft add rule ip {} {} udp dport {} drop",
            Self::TABLE_NAME, Self::CHAIN_NAME, self.config.game_port
        );
        Self::run_cmd(&rule2, false);

        // TCP rules - Queue for TLS port
        let rule3 = format!(
            "nft add rule ip {} {} tcp dport {} queue num {}",
            Self::TABLE_NAME, Self::CHAIN_NAME, self.config.tls_port, self.config.tcp_queue_num
        );
        Self::run_cmd(&rule3, false);

        tracing::info!("NFTables table '{}' created", Self::TABLE_NAME);
        true
    }

    pub fn cleanup(&self) {
        Self::run_cmd(&format!("nft delete table ip {}", Self::TABLE_NAME), true);
        tracing::info!("NFTables table '{}' deleted", Self::TABLE_NAME);
    }

    pub fn add_ip(&self, ip: &str) {
        let cmd = format!(
            "nft add element ip {} {} '{{ {} timeout {}s }}'",
            Self::TABLE_NAME, Self::SET_NAME, ip, self.config.trust_timeout_seconds
        );
        Self::run_cmd(&cmd, true);
    }

    pub fn remove_ip(&self, ip: &str) {
        let cmd = format!("nft delete element ip {} {} '{{ {} }}'", Self::TABLE_NAME, Self::SET_NAME, ip);
        Self::run_cmd(&cmd, true);
    }
}
