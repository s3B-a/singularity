use super::error::{Error, Result};
use super::packet::{PacketNumberSpace, Packet};
use super::congestion::{CongestionController, CongestionAlgorithm};
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossTimerType {
    Probe,
    LossDetection,
    ProbeTimeout,
}

#[derive(Debug, Clone)]
pub struct SentPacket {
    pub packet_number: u64,
    pub time_sent: Instant,
    pub size: usize,
    pub ack_eliciting: bool,
    pub ack_only: bool,
    pub pn_space: PacketNumberSpace,
    pub declared_lost: bool,
    pub acknowledged: bool,
}

impl SentPacket {
    pub fn new(packet_number: u64, size: usize, ack_eliciting: bool, pn_space: PacketNumberSpace) -> Self {
        Self {
            packet_number,
            time_sent: Instant::now(),
            size,
            ack_eliciting,
            ack_only: !ack_eliciting,
            pn_space,
            declared_lost: false,
            acknowledged: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RecoveryStatus {
    pub bytes_sent: u64,
    pub bytes_acked: u64,
    pub bytes_lost: u64,
    pub packets_in_flight: usize,
    pub probe_timeout_count: u32,
    pub smoothed_rtt: Option<Duration>,
    pub min_rtt: Option<Duration>,
    pub cwnd: u64,
}

pub struct RecoveryManager {
    sent_packets: BTreeMap<PacketNumberSpace, BTreeMap<u64, SentPacket>>,
    largest_acked: BTreeMap<PacketNumberSpace, u64>,
    latest_rtt: Option<Duration>,
    smoothed_rtt: Option<Duration>,
    rttvar: Duration,
    min_rtt: Option<Duration>,
    max_ack_delay: Duration,
    loss_time: BTreeMap<PacketNumberSpace, Option<Instant>>,
    probe_timeout_count: u32,
    time_of_last_ack_eliciting: BTreeMap<PacketNumberSpace, Option<Instant>>,
    cc: CongestionController,
    loss_threshold: f64,
    time_threshold: f64,
    initial_rtt: Duration,
    crypto_count: u32,
    bytes_sent: u64,
    bytes_acked: u64,
    bytes_lost: u64,
    lost_packets: VecDeque<u64>,
}

impl RecoveryManager {
    pub fn new(max_datagram_size: usize) -> Self {
        let mut sent_packets = BTreeMap::new();
        sent_packets.insert(PacketNumberSpace::Initial, BTreeMap::new());
        sent_packets.insert(PacketNumberSpace::Handshake, BTreeMap::new());
        sent_packets.insert(PacketNumberSpace::ApplicationData, BTreeMap::new());
        
        let mut largest_acked = BTreeMap::new();
        largest_acked.insert(PacketNumberSpace::Initial, 0);
        largest_acked.insert(PacketNumberSpace::Handshake, 0);
        largest_acked.insert(PacketNumberSpace::ApplicationData, 0);
        
        let mut time_of_last_ack_eliciting = BTreeMap::new();
        time_of_last_ack_eliciting.insert(PacketNumberSpace::Initial, None);
        time_of_last_ack_eliciting.insert(PacketNumberSpace::Handshake, None);
        time_of_last_ack_eliciting.insert(PacketNumberSpace::ApplicationData, None);
        
        let mut loss_time = BTreeMap::new();
        loss_time.insert(PacketNumberSpace::Initial, None);
        loss_time.insert(PacketNumberSpace::Handshake, None);
        loss_time.insert(PacketNumberSpace::ApplicationData, None);

        Self {
            sent_packets,
            largest_acked,
            latest_rtt: None,
            smoothed_rtt: None,
            rttvar: Duration::from_millis(0),
            min_rtt: None,
            max_ack_delay: Duration::from_millis(25),
            loss_time,
            probe_timeout_count: 0,
            time_of_last_ack_eliciting,
            cc: CongestionController::new(CongestionAlgorithm::Cubic, max_datagram_size as u64),
            loss_threshold: 3.0,
            time_threshold: 9.0 / 8.0,
            initial_rtt: Duration::from_millis(100),
            crypto_count: 0,
            bytes_sent: 0,
            bytes_acked: 0,
            bytes_lost: 0,
            lost_packets: VecDeque::new(),
        }
    }

    pub fn on_packet_sent(&mut self, pn_space: PacketNumberSpace, packet_number: u64, size: usize, ack_eliciting: bool) {
        let packet = SentPacket::new(packet_number, size, ack_eliciting, pn_space);
        if ack_eliciting {
            self.time_of_last_ack_eliciting.insert(pn_space, Some(Instant::now()));
        }

        self.sent_packets.get_mut(&pn_space).unwrap().insert(packet_number, packet);
        self.cc.on_packet_sent(size as u64);
        self.bytes_sent += size as u64;
    }

    pub fn on_ack_received(&mut self, pn_space: PacketNumberSpace, largest_acked: u64, ack_delay: Duration, acked_ranges: Vec<(u64, u64)>, now: Instant) -> Result<()> {
        let prev_largest = *self.largest_acked.get(&pn_space).unwrap_or(&0);
        if largest_acked > prev_largest {
            self.largest_acked.insert(pn_space, largest_acked);
        }

        let mut newly_acked = Vec::new();
        for (start, end) in acked_ranges {
            for pn in start..=end {
                if let Some(packet) = self.sent_packets.get_mut(&pn_space) {
                    if let Some(pack) = packet.get_mut(&pn) {
                        if !pack.acknowledged {
                            pack.acknowledged = true;
                            newly_acked.push(pack.clone());
                        }
                    }
                }
            }
        }

        if newly_acked.is_empty() {
            return Ok(());
        }

        if let Some(largest_newly_acked) = newly_acked.iter().max_by_key(|p| p.packet_number) {
            let latest_rtt = now.duration_since(largest_newly_acked.time_sent);
            self.update_rtt(latest_rtt, ack_delay);
        }

        let mut total_acked = 0;
        for packet in &newly_acked {
            total_acked += packet.size;
            self.bytes_acked += packet.size as u64;
        }

        if total_acked > 0 {
            let rtt = self.smoothed_rtt.unwrap_or(self.initial_rtt);
            self.cc.on_packet_acked(total_acked as u64, rtt, now)?;
        }

        self.detect_and_remove_lost_packets(pn_space, now);
        self.probe_timeout_count = 0;
        self.set_loss_detection_timer();

        Ok(())
    }

    fn update_rtt(&mut self, latest_rtt: Duration, ack_delay: Duration) {
        self.latest_rtt = Some(latest_rtt);
        self.min_rtt = Some(self.min_rtt.map_or(latest_rtt, |min| min.min(latest_rtt)));
        let adjusted_rtt = if latest_rtt > self.min_rtt.unwrap() + ack_delay {
            latest_rtt - ack_delay
        } else {
            latest_rtt
        };

        if let Some(srtt) = self.smoothed_rtt {
            let rttvar_sample = if srtt > adjusted_rtt {
                srtt - adjusted_rtt
            } else {
                adjusted_rtt - srtt
            };

            self.rttvar = (self.rttvar * 3 + rttvar_sample) / 4;
            self.smoothed_rtt = Some((srtt * 7 + adjusted_rtt) / 8);
        } else {
            self.smoothed_rtt = Some(adjusted_rtt);
            self.rttvar = adjusted_rtt / 2;
        }
    }

    fn detect_and_remove_lost_packets(&mut self, pn_space: PacketNumberSpace, now: Instant) -> Result<()> {
        let largest_acked = *self.largest_acked.get(&pn_space).unwrap_or(&0);
        let loss_delay = Duration::from_secs_f64(self.time_threshold * self.smoothed_rtt.unwrap_or(self.initial_rtt).as_secs_f64());
        let lost_send_time = now.checked_sub(loss_delay).unwrap_or(now);
        let packets = self.sent_packets.get_mut(&pn_space).unwrap();
        let mut loss_packets = Vec::new();
        for (&pn, packet) in packets.iter_mut() {
            if packet.acknowledged || packet.declared_lost {
                continue;
            }

            if largest_acked >= pn + self.loss_threshold as u64 {
                packet.declared_lost = true;
                loss_packets.push(packet.clone());
                continue;
            }

            if packet.time_sent < lost_send_time {
                packet.declared_lost = true;
                loss_packets.push(packet.clone());
                continue;
            }

            let loss_time = packet.time_sent + loss_delay;
            let current_loss_time = self.loss_time.get(&pn_space).unwrap();
            if current_loss_time.is_none() || loss_time < current_loss_time.unwrap() {
                self.loss_time.insert(pn_space, Some(loss_time));
            }
        }

        if !loss_packets.is_empty() {
            self.on_packets_lost(loss_packets, now)?;
        }

        Ok(())
    }

    fn on_packets_lost(&mut self, lost_packets: Vec<SentPacket>, now: Instant) -> Result<()> {
        let mut lost_bytes = 0;
        for packet in lost_packets {
            lost_bytes += packet.size;
            self.bytes_lost += packet.size as u64;
            if packet.ack_eliciting {
                self.lost_packets.push_back(packet.packet_number);
            }
        }

        if lost_bytes > 0 {
            self.cc.on_congestion_event(now)?;
        }

        Ok(())
    }

    pub fn probe_timeout(&self) -> Duration {
        let rtt = self.smoothed_rtt.unwrap_or(self.initial_rtt);
        let rtt_var = self.rttvar.max(Duration::from_millis(1));

        rtt + 4 * rtt_var + self.max_ack_delay
    }

    fn set_loss_detection_timer(&mut self) {
        let mut earliest_loss_time: Option<Instant> = None;
        for &space in &[
            PacketNumberSpace::Initial,
            PacketNumberSpace::Handshake,
            PacketNumberSpace::ApplicationData,
        ] {
            if let Some(Some(loss_time)) = self.loss_time.get(&space) {
                if earliest_loss_time.is_none() || *loss_time < earliest_loss_time.unwrap() {
                    earliest_loss_time = Some(*loss_time);
                }
            }
        }

        if earliest_loss_time.is_none() {
            return;
        }

        let now = Instant::now();
        if earliest_loss_time.unwrap() <= now {
            self.probe_timeout_count += 1;
            self.on_probe_timeout(now);
        } else {
            let delay = earliest_loss_time.unwrap() - now;
            let timer_type = if self.probe_timeout_count > 0 {
                LossTimerType::ProbeTimeout
            } else {
                LossTimerType::LossDetection
            };

            self.on_probe_timeout(now + delay);
        }
    }

    fn on_probe_timeout(&mut self, now: Instant) {
        self.probe_timeout_count += 1;
        self.cc.on_probe_timeout(now);
        if let Some(packet_number) = self.lost_packets.pop_front() {
            for space in &[PacketNumberSpace::Initial, PacketNumberSpace::Handshake, PacketNumberSpace::ApplicationData] {
                let lost_packet = if let Some(packet) = self.sent_packets.get_mut(space).unwrap().get_mut(&packet_number) {
                    if packet.ack_eliciting && !packet.acknowledged {
                        packet.declared_lost = true;
                        Some(packet.clone())
                    } else {
                        None
                    }
                } else {
                    None
                };
                
                if let Some(lost) = lost_packet {
                    self.on_packets_lost(vec![lost], now).unwrap();
                    break;
                }
            }
        }

        self.set_loss_detection_timer();
    }

    pub fn loss_detection_timeout(&mut self, now: Instant) -> Result<()> {
        for &space in &[
            PacketNumberSpace::Initial,
            PacketNumberSpace::Handshake,
            PacketNumberSpace::ApplicationData,
        ] {
            if let Some(Some(loss_time)) = self.loss_time.get(&space) {
                if now >= *loss_time {
                    self.detect_and_remove_lost_packets(space, now)?;
                }
            }
        }

        if self.has_ack_eliciting_in_flight() {
            self.probe_timeout_count += 1;
            self.on_probe_timeout(now);
        }

        self.set_loss_detection_timer();

        Ok(())
    }

    fn has_ack_eliciting_in_flight(&self) -> bool {
        for packets in self.sent_packets.values() {
            for packet in packets.values() {
                if packet.ack_eliciting && !packet.acknowledged && !packet.declared_lost {
                    return true;
                }
            }
        }

        false
    }

    pub fn get_lost_packets(&mut self) -> Vec<u64> {
        self.lost_packets.drain(..).collect()
    }

    pub fn discard_space(&mut self, pn_space: PacketNumberSpace) {
        self.sent_packets.get_mut(&pn_space).unwrap().clear();
        self.loss_time.insert(pn_space, None);
        self.time_of_last_ack_eliciting.insert(pn_space, None);
    }

    pub fn smoothed_rtt(&self) -> Option<Duration>{
        self.smoothed_rtt
    }

    pub fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt
    }

    pub fn latest_rtt(&self) -> Option<Duration> {
        self.latest_rtt
    }

    pub fn rttvar(&self) -> Duration {
        self.rttvar
    }

    pub fn cc(&self) -> &CongestionController {
        &self.cc
    }

    pub fn cc_mut(&mut self) -> &mut CongestionController {
        &mut self.cc
    }

    pub fn bytes_in_flight(&self) -> u64 {
        self.cc.bytes_in_flight()
    }

    pub fn cwnd(&self) -> u64 {
        self.cc.cwnd()
    }

    pub fn stats(&self) -> RecoveryStatus {
        RecoveryStatus {
            bytes_sent: self.bytes_sent,
            bytes_acked: self.bytes_acked,
            bytes_lost: self.bytes_lost,
            packets_in_flight: self.sent_packets.values().map(|packets| packets.values().filter(|p| !p.acknowledged && !p.declared_lost).count()).sum(),
            probe_timeout_count: self.probe_timeout_count,
            smoothed_rtt: self.smoothed_rtt,
            min_rtt: self.min_rtt,
            cwnd: self.cc.cwnd(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_recovery_manager_creation() {
        let rm = RecoveryManager::new(1200);
        assert_eq!(rm.bytes_sent, 0);
        assert_eq!(rm.bytes_acked, 0);
        assert_eq!(rm.bytes_lost, 0);
        assert_eq!(rm.probe_timeout_count, 0);
    }
    
    #[test]
    fn test_packet_sent() {
        let mut rm = RecoveryManager::new(1200);
        
        rm.on_packet_sent(PacketNumberSpace::ApplicationData, 0, 1000, true);
        
        let stats = rm.stats();
        assert_eq!(stats.bytes_sent, 1000);
        assert_eq!(stats.packets_in_flight, 1);
    }
    
    #[test]
    fn test_ack_received() {
        let mut rm = RecoveryManager::new(1200);
        let now = Instant::now();
        
        rm.on_packet_sent(PacketNumberSpace::ApplicationData, 0, 1000, true);
        
        rm.on_ack_received(
            PacketNumberSpace::ApplicationData,
            0,
            Duration::from_millis(10),
            vec![(0, 0)],
            now,
        ).unwrap();
        
        let stats = rm.stats();
        assert_eq!(stats.bytes_acked, 1000);
        assert!(stats.smoothed_rtt.is_some());
    }
    
    #[test]
    fn test_rtt_calculation() {
        let mut rm = RecoveryManager::new(1200);
        let now = Instant::now();
        
        let rtt = Duration::from_millis(50);
        rm.update_rtt(rtt, Duration::from_millis(0));
        
        assert_eq!(rm.smoothed_rtt(), Some(rtt));
        assert_eq!(rm.min_rtt(), Some(rtt));
        assert_eq!(rm.latest_rtt(), None);
    }
    
    #[test]
    fn test_loss_detection() {
        let mut rm = RecoveryManager::new(1200);
        let now = Instant::now();
        
        for i in 0..5 {
            rm.on_packet_sent(PacketNumberSpace::ApplicationData, i, 1000, true);
        }
        
        rm.on_ack_received(
            PacketNumberSpace::ApplicationData,
            4,
            Duration::from_millis(10),
            vec![(4, 4)],
            now,
        ).unwrap();
        
        let lost = rm.get_lost_packets();
        assert!(!lost.is_empty());
    }
    
    #[test]
    fn test_pto_calculation() {
        let mut rm = RecoveryManager::new(1200);
        
        rm.smoothed_rtt = Some(Duration::from_millis(100));
        rm.rttvar = Duration::from_millis(10);
        
        let pto = rm.probe_timeout();
        assert!(pto > Duration::from_millis(100));
    }
    
    #[test]
    fn test_discard_space() {
        let mut rm = RecoveryManager::new(1200);
        
        rm.on_packet_sent(PacketNumberSpace::Initial, 0, 1000, true);
        rm.on_packet_sent(PacketNumberSpace::ApplicationData, 0, 1000, true);
        
        rm.discard_space(PacketNumberSpace::Initial);
        
        assert_eq!(
            rm.sent_packets.get(&PacketNumberSpace::Initial).unwrap().len(),
            0
        );
        assert_eq!(
            rm.sent_packets.get(&PacketNumberSpace::ApplicationData).unwrap().len(),
            1
        );
    }
    
    #[test]
    fn test_statistics() {
        let mut rm = RecoveryManager::new(1200);
        let now = Instant::now();
        
        rm.on_packet_sent(PacketNumberSpace::ApplicationData, 0, 1000, true);
        rm.on_packet_sent(PacketNumberSpace::ApplicationData, 1, 1000, true);
        
        rm.on_ack_received(
            PacketNumberSpace::ApplicationData,
            0,
            Duration::from_millis(10),
            vec![(0, 0)],
            now,
        ).unwrap();
        
        let stats = rm.stats();
        assert_eq!(stats.bytes_sent, 2000);
        assert_eq!(stats.bytes_acked, 1000);
        assert_eq!(stats.packets_in_flight, 1);
    }
    
    #[test]
    fn test_multiple_ack_ranges() {
        let mut rm = RecoveryManager::new(1200);
        let now = Instant::now();
        
        for i in 0..10 {
            rm.on_packet_sent(PacketNumberSpace::ApplicationData, i, 1000, true);
        }
        
        rm.on_ack_received(
            PacketNumberSpace::ApplicationData,
            7,
            Duration::from_millis(10),
            vec![(0, 2), (5, 7)],
            now,
        ).unwrap();
        
        let stats = rm.stats();
        assert_eq!(stats.bytes_acked, 6000);
    }
}