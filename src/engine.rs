use std::sync::Arc;
use std::thread;
use nfq::{Queue, Verdict};
use crate::config::FirewallConfig;
use crate::tracker::ConnectionTracker;
use crate::processor::PacketProcessor;
use crate::models::PacketVerdict;

pub struct FirewallEngine {
    config: Arc<FirewallConfig>,
    tracker: Arc<ConnectionTracker>,
    processor: Arc<PacketProcessor>,
}

impl FirewallEngine {
    pub fn new(config: Arc<FirewallConfig>, tracker: Arc<ConnectionTracker>, processor: Arc<PacketProcessor>) -> Self {
        Self { config, tracker, processor }
    }

    pub fn start(&self) {
        let tcp_queue_num = self.config.tcp_queue_num;
        let processor_clone = self.processor.clone();
        
        // Spawn TCP Worker
        thread::spawn(move || {
            Self::worker_process(tcp_queue_num, processor_clone);
        });

        // Spawn UDP Workers
        let start_q = self.config.udp_queue_start;
        let count = self.config.udp_queue_count;

        for i in 0..count {
            let q_num = start_q + i;
            let processor_clone = self.processor.clone();
            thread::spawn(move || {
                Self::worker_process(q_num, processor_clone);
            });
        }
        
        tracing::info!("All worker processes started");
    }

    fn worker_process(queue_num: u16, processor: Arc<PacketProcessor>) {
        tracing::info!("Worker started on Queue {}", queue_num);
        let mut queue = match Queue::open() {
            Ok(q) => q,
            Err(e) => {
                tracing::error!("Failed to open NFQueue: {}", e);
                return;
            }
        };

        if let Err(e) = queue.bind(queue_num) {
            tracing::error!("Failed to bind to Queue {}: {}", queue_num, e);
            return;
        }

        loop {
            let mut msg = match queue.recv() {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!("Failed to receive message on Queue {}: {}", queue_num, e);
                    continue;
                }
            };

            let payload = msg.get_payload();
            let verdict = processor.process(payload);

            let v = match verdict {
                PacketVerdict::Accept => Verdict::Accept,
                PacketVerdict::Drop => Verdict::Drop,
            };

            msg.set_verdict(v);
        }
    }
}
