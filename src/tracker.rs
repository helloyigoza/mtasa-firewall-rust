use std::sync::Arc;
use std::time::Instant;
use dashmap::DashMap;
use crate::models::{IPRecord, IPState};
use crate::config::FirewallConfig;
use crate::nftables::NftablesManager;

pub struct ConnectionTracker {
    config: Arc<FirewallConfig>,
    nft_manager: Option<Arc<NftablesManager>>,
    records: DashMap<String, IPRecord>,
}

impl ConnectionTracker {
    pub fn new(config: Arc<FirewallConfig>, nft_manager: Option<Arc<NftablesManager>>) -> Self {
        Self {
            config,
            nft_manager,
            records: DashMap::new(),
        }
    }

    pub fn get_state(&self, ip: &str) -> IPState {
        self.records.get(ip).map(|r| r.state).unwrap_or(IPState::Unknown)
    }

    pub fn set_syn_received(&self, ip: &str) {
        let mut record = self.records.entry(ip.to_string()).or_insert_with(|| IPRecord::new(ip.to_string()));
        record.update_seen();
        if record.state == IPState::Unknown {
            record.transition_to(IPState::SynReceived);
            tracing::debug!("IP {} -> SYN_RECEIVED", ip);
        }
    }

    pub fn set_handshake_complete(&self, ip: &str) {
        let mut record = self.records.entry(ip.to_string()).or_insert_with(|| IPRecord::new(ip.to_string()));
        record.update_seen();
        if record.state == IPState::SynReceived {
            record.transition_to(IPState::HandshakeComplete);
            if let Some(ref nft) = self.nft_manager {
                nft.add_ip(ip);
            }
            tracing::info!("IP {} -> HANDSHAKE_COMPLETE (anti-spoof verified)", ip);
        }
    }

    pub fn set_pending(&self, ip: &str) {
        let mut record = self.records.entry(ip.to_string()).or_insert_with(|| IPRecord::new(ip.to_string()));
        record.update_seen();
        if matches!(record.state, IPState::Unknown | IPState::HandshakeComplete) {
            record.transition_to(IPState::Pending);
            tracing::debug!("IP {} -> PENDING", ip);
        }
    }

    pub fn set_trusted(&self, ip: &str) {
        let mut record = self.records.entry(ip.to_string()).or_insert_with(|| IPRecord::new(ip.to_string()));
        record.update_seen();
        if matches!(record.state, IPState::Unknown | IPState::Pending | IPState::SynReceived | IPState::HandshakeComplete) {
            record.transition_to(IPState::Trusted);
            if let Some(ref nft) = self.nft_manager {
                nft.add_ip(ip);
            }
            tracing::info!("IP {} -> TRUSTED", ip);
        }
    }

    pub fn set_blacklisted(&self, ip: &str) {
        let mut record = self.records.entry(ip.to_string()).or_insert_with(|| IPRecord::new(ip.to_string()));
        record.update_seen();
        if record.state != IPState::Blacklisted {
            record.transition_to(IPState::Blacklisted);
            if let Some(ref nft) = self.nft_manager {
                nft.remove_ip(ip);
            }
            tracing::warn!("IP {} -> BLACKLISTED (spam detected)", ip);
        }
    }

    pub fn is_verified(&self, ip: &str) -> bool {
        let state = self.get_state(ip);
        matches!(state, IPState::HandshakeComplete | IPState::Trusted)
    }

    pub fn is_trusted(&self, ip: &str) -> bool {
        self.get_state(ip) == IPState::Trusted
    }

    pub fn is_blacklisted(&self, ip: &str) -> bool {
        self.get_state(ip) == IPState::Blacklisted
    }

    pub fn record_packet(&self, ip: &str) -> bool {
        let mut record = self.records.entry(ip.to_string()).or_insert_with(|| IPRecord::new(ip.to_string()));
        record.update_seen();
        
        let now = Instant::now();
        let window_secs = self.config.spam_window_seconds;
        
        record.packet_timestamps.retain(|&ts| now.duration_since(ts).as_secs() <= window_secs);
        record.packet_timestamps.push(now);
        
        record.packet_timestamps.len() as u32 > self.config.spam_threshold_packets
    }

    pub fn cleanup_expired(&self) {
        let mut to_remove = Vec::new();

        for mut entry in self.records.iter_mut() {
            let ip = entry.key().clone();
            let record = entry.value_mut();

            match record.state {
                IPState::Trusted => {
                    if record.is_expired(self.config.trust_timeout_seconds) {
                        record.transition_to(IPState::Unknown);
                        if let Some(ref nft) = self.nft_manager {
                            nft.remove_ip(&ip);
                        }
                        tracing::debug!("IP {} trust expired", ip);
                    }
                }
                IPState::Pending => {
                    if record.is_expired(self.config.pending_timeout_seconds) {
                        record.transition_to(IPState::Unknown);
                        tracing::debug!("IP {} pending expired", ip);
                    }
                }
                IPState::Blacklisted => {
                    if record.is_expired(self.config.blacklist_duration_seconds) {
                        record.transition_to(IPState::Unknown);
                        tracing::info!("IP {} blacklist expired", ip);
                    }
                }
                IPState::Unknown => {
                    if record.last_seen.elapsed().as_secs() > 3600 {
                        to_remove.push(ip);
                    }
                }
                _ => {}
            }
        }

        for ip in to_remove {
            self.records.remove(&ip);
            if let Some(ref nft) = self.nft_manager {
                nft.remove_ip(&ip);
            }
            tracing::debug!("IP {} removed from tracker", ip);
        }
    }
}
