use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IPState {
    Unknown,
    SynReceived,
    HandshakeComplete,
    Pending,
    Trusted,
    Blacklisted,
}

#[derive(Debug, Clone)]
pub struct IPRecord {
    pub address: String,
    pub state: IPState,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub state_changed_at: Instant,
    pub packet_timestamps: Vec<Instant>,
}

impl IPRecord {
    pub fn new(address: String) -> Self {
        let now = Instant::now();
        Self {
            address,
            state: IPState::Unknown,
            first_seen: now,
            last_seen: now,
            state_changed_at: now,
            packet_timestamps: Vec::new(),
        }
    }

    pub fn update_seen(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn transition_to(&mut self, new_state: IPState) {
        self.state = new_state;
        self.state_changed_at = Instant::now();
    }

    pub fn is_expired(&self, timeout_secs: u64) -> bool {
        self.state_changed_at.elapsed().as_secs() > timeout_secs
    }
}

pub enum PacketVerdict {
    Accept,
    Drop,
}

#[derive(Debug)]
pub struct PacketInfo<'a> {
    pub src_ip: std::net::Ipv4Addr,
    pub dst_ip: std::net::Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8, // 6 for TCP, 17 for UDP
    pub length: u16,
    pub tcp_flags: Option<u8>,
    pub payload: &'a [u8],
}
