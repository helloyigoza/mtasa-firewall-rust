use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct FirewallConfig {
    pub game_port: u16,
    pub server_list_port: u16,
    pub tls_port: u16,
    pub udp_join_length_min: u16,
    pub udp_join_length_max: u16,
    pub spam_threshold_packets: u32,
    pub spam_window_seconds: u64,
    pub trust_timeout_seconds: u64,
    pub pending_timeout_seconds: u64,
    pub blacklist_duration_seconds: u64,
    pub whitelist_ips: Vec<String>,
    pub tcp_queue_num: u16,
    pub udp_queue_start: u16,
    pub udp_queue_count: u16,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            game_port: 22003,
            server_list_port: 22126,
            tls_port: 443,
            udp_join_length_min: 45,
            udp_join_length_max: 90,
            spam_threshold_packets: 100,
            spam_window_seconds: 1,
            trust_timeout_seconds: 3600,
            pending_timeout_seconds: 60,
            blacklist_duration_seconds: 3600,
            whitelist_ips: vec![],
            tcp_queue_num: 1,
            udp_queue_start: 2,
            udp_queue_count: 1,
        }
    }
}

impl FirewallConfig {
    pub fn is_valid_join_length(&self, length: u16) -> bool {
        length >= self.udp_join_length_min && length <= self.udp_join_length_max
    }
}
