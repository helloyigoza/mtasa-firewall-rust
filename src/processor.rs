use std::sync::Arc;
use etherparse::{SlicedPacket, NetSlice, TransportSlice, TcpHeader};
use crate::config::FirewallConfig;
use crate::models::PacketVerdict;
use crate::tracker::ConnectionTracker;
use std::net::Ipv4Addr;

pub struct PacketProcessor {
    config: Arc<FirewallConfig>,
    tracker: Arc<ConnectionTracker>,
}

impl PacketProcessor {
    pub fn new(config: Arc<FirewallConfig>, tracker: Arc<ConnectionTracker>) -> Self {
        Self { config, tracker }
    }

    pub fn process(&self, raw_data: &[u8]) -> PacketVerdict {
        match SlicedPacket::from_ip(raw_data) {
            Ok(value) => {
                let (src_ip, _dst_ip) = match value.net {
                    Some(NetSlice::Ipv4(ref ip)) => {
                        (Ipv4Addr::from(ip.header().source()), Ipv4Addr::from(ip.header().destination()))
                    },
                    _ => return PacketVerdict::Accept,
                };

                let ip_str = src_ip.to_string();

                match value.transport {
                    Some(TransportSlice::Tcp(ref tcp)) => {
                        let payload = match &value.transport {
                            Some(TransportSlice::Tcp(t)) => t.payload(),
                            _ => &[],
                        };
                        self.handle_tcp(&ip_str, &tcp.to_header(), payload)
                    },
                    Some(TransportSlice::Udp(ref udp)) => {
                        let payload = match &value.transport {
                            Some(TransportSlice::Udp(u)) => u.payload(),
                            _ => &[],
                        };
                        self.handle_udp(&ip_str, udp.source_port(), udp.destination_port(), payload.len() as u16)
                    },
                    _ => PacketVerdict::Accept,
                }
            }
            Err(_) => PacketVerdict::Accept,
        }
    }

    fn handle_tcp(&self, ip_str: &str, tcp: &TcpHeader, payload: &[u8]) -> PacketVerdict {
        if tcp.syn {
            // Note: We should technically send a SYN-ACK here if we are implementing full userspace syncookies.
            // For now, we mimic the python structure but keep it simple.
            self.tracker.set_syn_received(ip_str);
            tracing::info!("TCP SYN from {}:{}", ip_str, tcp.source_port);
            // In python, it returns DROP because it manually sends a SYN-ACK.
            // Since we rely on kernel TCP stack or just passive tracking here, we accept it.
            // If full anti-spoofing is needed, we would craft a raw SYN-ACK packet and return Drop.
            return PacketVerdict::Accept; 
        }

        if tcp.ack {
            self.tracker.set_handshake_complete(ip_str);
        }

        // TLS Client Hello Check
        if payload.len() >= 6 && payload[0] == 0x16 && payload[5] == 0x01 {
            self.tracker.set_trusted(ip_str);
            tracing::info!("TLS Client Hello from {} - TRUSTED", ip_str);
        }

        PacketVerdict::Accept
    }

    fn handle_udp(&self, ip_str: &str, _src_port: u16, dst_port: u16, length: u16) -> PacketVerdict {
        if self.tracker.is_blacklisted(ip_str) {
            return PacketVerdict::Drop;
        }

        if dst_port == self.config.server_list_port {
            if self.tracker.record_packet(ip_str) {
                self.tracker.set_blacklisted(ip_str);
                tracing::warn!("Spam detected from {}, blacklisting", ip_str);
                return PacketVerdict::Drop;
            }
            return PacketVerdict::Accept;
        }

        if dst_port == self.config.game_port {
            if self.config.is_valid_join_length(length) {
                if self.tracker.is_verified(ip_str) {
                    self.tracker.set_trusted(ip_str);
                    return PacketVerdict::Accept;
                } else {
                    tracing::warn!("DROP unverified join attempt: {} (len={}) - Needs TCP/TLS verification first!", ip_str, length);
                    return PacketVerdict::Drop;
                }
            } else {
                return PacketVerdict::Drop;
            }
        }

        PacketVerdict::Drop
    }
}
