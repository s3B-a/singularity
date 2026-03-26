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
        let loss_delay = Duration::from_secs_f64(
            self.time_threshold * self.smoothed_rtt.unwrap_or(self.initial_rtt).as_secs_f64()
        );

        let lost_send_time = now.checked_sub(loss_delay).unwrap_or(now);
        let packets = self.sent_packets.get_mut(&pn_space).unwrap();
        let mut loss_packets = Vec::new();
        for (&pn, packet) in packets.iter_mut() {
            if pn < largest_acked.saturating_sub(3) {
                if !packet.declared_lost {
                    loss_packets.push(packet.clone());
                    packet.declared_lost = true;
                }
            } else if packet.time_sent < lost_send_time && !packet.declared_lost {
                loss_packets.push(packet.clone());
                packet.declared_lost = true;
            }
        }

        if !loss_packets.is_empty() {
            self.on_packets_lost(loss_packets, now)?;
        }

        Ok(())
    }

    fn on_packets_lost(&mut self, lost_packets: Vec<SentPacket>, now: Instant) -> Result<()> {
        let mut lost_bytes = 0u64;
        for packet in lost_packets {
            self.lost_packets.push_back(packet.packet_number);
            lost_bytes += packet.size as u64;
        }

        if lost_bytes > 0 {
            self.bytes_lost = self.bytes_lost.saturating_add(lost_bytes);
            self.cc.on_congestion_event(now)?;
        }

        Ok(())
    }

    pub fn on_ack_received(&mut self, pn_space: PacketNumberSpace, largest_acked: u64, ack_delay: Duration, acked_ranges: Vec<(u64, u64)>, now: Instant) -> Result<()> {
        let prev_largest = *self.largest_acked.get(&pn_space).unwrap_or(&0);
        if largest_acked <= prev_largest {
            return Ok(());
        }

        self.largest_acked.insert(pn_space, largest_acked);
        let mut newly_acked = Vec::new();
        for (start, end) in acked_ranges {
            for pn in start..=end {
                if let Some(packets) = self.sent_packets.get_mut(&pn_space) {
                    if let Some(packet) = packets.get_mut(&pn) {
                        if !packet.acknowledged {
                            newly_acked.push(packet.clone());
                            packet.acknowledged = true;
                        }
                    }
                }
            }
        }

        if newly_acked.is_empty() {
            return Ok(());
        }

        if let Some(largest_acked_packet) = newly_acked.iter().max_by_key(|p| p.packet_number) {
            let latest_rtt = largest_acked_packet.time_sent.elapsed();
            self.update_rtt(latest_rtt, ack_delay);
        }

        let mut total_acked = 0u64;
        for packet in &newly_acked {
            total_acked += packet.size as u64;
            self.bytes_acked += packet.size as u64;
        }

        if total_acked > 0 {
            self.cc.on_packet_acked(total_acked, self.smoothed_rtt.unwrap_or(self.initial_rtt), now)?;
        }

        self.detect_and_remove_lost_packets(pn_space, now)?;
        
        self.probe_timeout_count = 0;
        self.set_loss_detection_timer();

        Ok(())
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
            self.on_probe_timeout(now);
        }
    }

    fn on_probe_timeout(&mut self, _now: Instant) {
        self.probe_timeout_count = self.probe_timeout_count.saturating_add(1);
        if let Some(packet_number) = self.find_oldest_unacked_packet() {
            self.lost_packets.push_back(packet_number);
        }

        self.set_loss_detection_timer();
    }

    fn find_oldest_unacked_packet(&self) -> Option<u64> {
        for &space in &[
            PacketNumberSpace::Initial,
            PacketNumberSpace::Handshake,
            PacketNumberSpace::ApplicationData,
        ] {
            if let Some(packets) = self.sent_packets.get(&space) {
                for (&pn, packet) in packets.iter() {
                    if !packet.acknowledged && packet.ack_eliciting {
                        return Some(pn);
                    }
                }
            }
        }
        None
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

    pub fn probe_timeout(&self) -> Duration {
        let rtt = self.smoothed_rtt.unwrap_or(self.initial_rtt);
        let pto = rtt + (self.rttvar * 4);
        pto.max(Duration::from_millis(1))
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
    fn test_loss_detection() {
        let mut rm = RecoveryManager::new(1200);
        let now = Instant::now();
        
        rm.on_packet_sent(PacketNumberSpace::ApplicationData, 0, 1000, true);
        rm.on_packet_sent(PacketNumberSpace::ApplicationData, 1, 1000, true);
        rm.on_packet_sent(PacketNumberSpace::ApplicationData, 2, 1000, true);
        
        let ack_ranges = vec![(2, 2)];
        let result = rm.on_ack_received(
            PacketNumberSpace::ApplicationData,
            2,
            Duration::from_millis(10),
            ack_ranges,
            now,
        );
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_rtt_calculation() {
        let mut rm = RecoveryManager::new(1200);
        
        let rtt = Duration::from_millis(50);
        rm.update_rtt(rtt, Duration::from_millis(5));
        
        assert!(rm.smoothed_rtt.is_some());
        assert!(rm.min_rtt.is_some());
    }

    #[test]
    fn test_pto_calculation() {
        let mut rm = RecoveryManager::new(1200);
        rm.update_rtt(Duration::from_millis(50), Duration::from_millis(5));
        
        let pto = rm.probe_timeout();
        assert!(pto > Duration::from_millis(50));
    }

    #[test]
    fn test_discard_space() {
        let mut rm = RecoveryManager::new(1200);
        rm.on_packet_sent(PacketNumberSpace::Initial, 0, 1000, true);
        
        rm.discard_space(PacketNumberSpace::Initial);
        
        let stats = rm.stats();
        assert_eq!(stats.packets_in_flight, 0);
    }
}