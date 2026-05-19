use super::congestion::{CongestionAlgorithm, CongestionController};
use super::error::Result;
use super::packet::PacketNumberSpace;
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RECOVERY_STATUS_BLOB_MAGIC: &str = "SINGULARITY_HTTP3_RECOVERY_STATUS_BLOB_V1";
const RECOVERY_STATUS_BLOB_CONTEXT: &str = "SINGULARITY_HTTP3_RECOVERY_STATUS_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureRecoveryStatusBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

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
    pub fn new( packet_number: u64, size: usize, ack_eliciting: bool, pn_space: PacketNumberSpace) -> Self {
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

impl RecoveryStatus {
    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureRecoveryStatusBlobMeta, Vec<u8>)> {
        let mut selected_algorithm = algorithm;
        if !selected_algorithm.is_implemented() {
            selected_algorithm = CompressionAlgorithm::Identity;
        }

        let raw_payload = serialize_recovery_status(self);
        let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
            raw_payload.clone()
        } else {
            compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
        };

        let nonce = random::generate_random(24).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate secure recovery-status nonce: {}", e),
            )
        })?;

        let digest = sha256(&raw_payload);
        let tag = compute_recovery_status_blob_tag(
            &nonce,
            selected_algorithm,
            raw_payload.len(),
            &encoded_payload,
        );

        let meta = SecureRecoveryStatusBlobMeta {
            algorithm: selected_algorithm,
            nonce_b64: pem::encode(&nonce),
            digest_b64: pem::encode(&digest),
            tag_b64: pem::encode(&tag),
            raw_size: raw_payload.len(),
            encoded_size: encoded_payload.len(),
            issued_at_unix: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        };

        let header = format!(
            "{magic}\ncontent-encoding={encoding}\nnonce={nonce}\ndigest=SHA-256={digest}\ntag=HMAC-SHA-256={tag}\nraw-size={raw_size}\nencoded-size={encoded_size}\nissued-at={issued_at}\n\n",
            magic = RECOVERY_STATUS_BLOB_MAGIC,
            encoding = meta.algorithm.content_encoding(),
            nonce = meta.nonce_b64,
            digest = meta.digest_b64,
            tag = meta.tag_b64,
            raw_size = meta.raw_size,
            encoded_size = meta.encoded_size,
            issued_at = meta.issued_at_unix,
        );

        let mut blob = header.into_bytes();
        blob.extend_from_slice(&encoded_payload);

        Ok((meta, blob))
    }

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureRecoveryStatusBlobMeta, Vec<u8>)> {
        self.to_secure_blob(select_secure_recovery_status_algorithm(accept_encoding))
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureRecoveryStatusBlobMeta, Self)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_recovery_status_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid recovery-status nonce encoding: {}", e),
            )
        })?;

        let digest = pem::decode(&meta.digest_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid recovery-status digest encoding: {}", e),
            )
        })?;

        let tag = pem::decode(&meta.tag_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid recovery-status tag encoding: {}", e),
            )
        })?;

        if digest.len() != 32 || tag.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recovery-status digest or tag has invalid length",
            ));
        }

        let expected_tag = compute_recovery_status_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);
        if !constant_time_eq(&expected_tag, &tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure recovery-status blob tag verification failed",
            ));
        }

        let raw_payload = if meta.algorithm == CompressionAlgorithm::Identity {
            body.to_vec()
        } else {
            compression::decompress(meta.algorithm, body)?
        };

        if raw_payload.len() != meta.raw_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "recovery-status raw-size mismatch: expected {}, got {}",
                    meta.raw_size,
                    raw_payload.len()
                ),
            ));
        }

        let computed_digest = sha256(&raw_payload);
        if !constant_time_eq(&computed_digest, &digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure recovery-status blob digest verification failed",
            ));
        }

        let status = deserialize_recovery_status(&raw_payload)?;
        Ok((meta, status))
    }
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
            self.time_threshold * self.smoothed_rtt.unwrap_or(self.initial_rtt).as_secs_f64(),
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
                for (&pn, packet) in packets {
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

    pub fn smoothed_rtt(&self) -> Option<Duration> {
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

pub fn select_secure_recovery_status_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_recovery_status(status: &RecoveryStatus, algorithm: CompressionAlgorithm) -> io::Result<(SecureRecoveryStatusBlobMeta, Vec<u8>)> {
    status.to_secure_blob(algorithm)
}

pub fn encode_secure_recovery_status_auto(status: &RecoveryStatus, accept_encoding: &str) -> io::Result<(SecureRecoveryStatusBlobMeta, Vec<u8>)> {
    status.to_secure_blob_auto(accept_encoding)
}

pub fn decode_secure_recovery_status(data: &[u8]) -> io::Result<(SecureRecoveryStatusBlobMeta, RecoveryStatus)> {
    RecoveryStatus::from_secure_blob(data)
}

fn serialize_recovery_status(status: &RecoveryStatus) -> Vec<u8> {
    format!(
        "bytes-sent={}\nbytes-acked={}\nbytes-lost={}\npackets-in-flight={}\nprobe-timeout-count={}\nsmoothed-rtt-ms={}\nmin-rtt-ms={}\ncwnd={}\n",
        status.bytes_sent,
        status.bytes_acked,
        status.bytes_lost,
        status.packets_in_flight,
        status.probe_timeout_count,
        opt_duration_ms_to_text(status.smoothed_rtt),
        opt_duration_ms_to_text(status.min_rtt),
        status.cwnd,
    )
    .into_bytes()
}

fn deserialize_recovery_status(raw_payload: &[u8]) -> io::Result<RecoveryStatus> {
    let payload = std::str::from_utf8(raw_payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "recovery-status payload is not valid utf-8",
        )
    })?;

    let mut map = HashMap::new();
    for line in payload.lines() {
        let (key, value) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid recovery-status payload line '{}'", line),
            )
        })?;

        map.insert(key.trim().to_string(), value.trim().to_string());
    }

    let parse_u64 = |key: &str| -> io::Result<u64> {
        map.get(key).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing '{}' in recovery-status payload", key),
            )
        })?.parse::<u64>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid '{}' in recovery-status payload", key),
            )
        })
    };

    let parse_usize = |key: &str| -> io::Result<usize> {
        map.get(key).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing '{}' in recovery-status payload", key),
            )
        })?.parse::<usize>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid '{}' in recovery-status payload", key),
            )
        })
    };

    let parse_u32 = |key: &str| -> io::Result<u32> {
        map.get(key).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing '{}' in recovery-status payload", key),
            )
        })?.parse::<u32>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid '{}' in recovery-status payload", key),
            )
        })
    };

    let smoothed_rtt = parse_opt_duration_ms(
        map.get("smoothed-rtt-ms")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing smoothed-rtt-ms in recovery-status payload"))?,
    )?;
    let min_rtt = parse_opt_duration_ms(
        map.get("min-rtt-ms")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing min-rtt-ms in recovery-status payload"))?,
    )?;

    Ok(RecoveryStatus {
        bytes_sent: parse_u64("bytes-sent")?,
        bytes_acked: parse_u64("bytes-acked")?,
        bytes_lost: parse_u64("bytes-lost")?,
        packets_in_flight: parse_usize("packets-in-flight")?,
        probe_timeout_count: parse_u32("probe-timeout-count")?,
        smoothed_rtt,
        min_rtt,
        cwnd: parse_u64("cwnd")?,
    })
}

fn opt_duration_ms_to_text(value: Option<Duration>) -> String {
    value.map(|d| d.as_millis().to_string()).unwrap_or_else(|| "-".to_string())
}

fn parse_opt_duration_ms(value: &str) -> io::Result<Option<Duration>> {
    if value.trim() == "-" {
        return Ok(None);
    }

    let ms = value.trim().parse::<u64>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid duration-ms value '{}'", value),
        )
    })?;
    Ok(Some(Duration::from_millis(ms)))
}

fn compute_recovery_status_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(RECOVERY_STATUS_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(RECOVERY_STATUS_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "recovery-status header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "recovery-status header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "recovery-status blob missing header/body separator",
    ))
}

fn parse_secure_recovery_status_meta(header: &str, body_len: usize) -> io::Result<SecureRecoveryStatusBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != RECOVERY_STATUS_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid secure recovery-status blob magic",
        ));
    }

    let mut algorithm = CompressionAlgorithm::Identity;
    let mut nonce_b64 = None;
    let mut digest_b64 = None;
    let mut tag_b64 = None;
    let mut raw_size = None;
    let mut encoded_size = None;
    let mut issued_at_unix = None;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let (k, v) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid secure recovery-status header line '{}'", line),
            )
        })?;

        match k.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unsupported content-encoding '{}'", v.trim()),
                    )
                })?;
            }
            "nonce" => nonce_b64 = Some(v.trim().to_string()),
            "digest" => {
                let parsed = v.trim().strip_prefix("SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid digest header")
                })?.to_string();

                digest_b64 = Some(parsed);
            }
            "tag" => {
                let parsed = v.trim().strip_prefix("HMAC-SHA-256=").ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid tag header")
                })?.to_string();

                tag_b64 = Some(parsed);
            }
            "raw-size" => {
                raw_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid raw-size in recovery-status blob",
                    )
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid encoded-size in recovery-status blob",
                    )
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid issued-at in recovery-status blob",
                    )
                })?);
            }
            _ => {}
        }
    }

    let meta = SecureRecoveryStatusBlobMeta {
        algorithm,
        nonce_b64: nonce_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing nonce in secure recovery-status blob header",
            )
        })?,
        digest_b64: digest_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing digest in secure recovery-status blob header",
            )
        })?,
        tag_b64: tag_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing tag in secure recovery-status blob header",
            )
        })?,
        raw_size: raw_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing raw-size in secure recovery-status blob header",
            )
        })?,
        encoded_size: encoded_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing encoded-size in secure recovery-status blob header",
            )
        })?,
        issued_at_unix: issued_at_unix.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing issued-at in secure recovery-status blob header",
            )
        })?,
    };

    if meta.encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "recovery-status encoded-size mismatch: expected {}, got {}",
                meta.encoded_size, body_len
            ),
        ));
    }

    Ok(meta)
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

    #[test]
    fn test_secure_recovery_status_roundtrip_identity() {
        let status = RecoveryStatus {
            bytes_sent: 12,
            bytes_acked: 11,
            bytes_lost: 1,
            packets_in_flight: 3,
            probe_timeout_count: 2,
            smoothed_rtt: Some(Duration::from_millis(45)),
            min_rtt: Some(Duration::from_millis(20)),
            cwnd: 10000,
        };

        let (meta, blob) =
            encode_secure_recovery_status(&status, CompressionAlgorithm::Identity).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (_decoded_meta, decoded) = decode_secure_recovery_status(&blob).unwrap();
        assert_eq!(decoded.bytes_sent, status.bytes_sent);
        assert_eq!(decoded.bytes_acked, status.bytes_acked);
        assert_eq!(decoded.bytes_lost, status.bytes_lost);
        assert_eq!(decoded.packets_in_flight, status.packets_in_flight);
        assert_eq!(decoded.probe_timeout_count, status.probe_timeout_count);
        assert_eq!(decoded.smoothed_rtt, status.smoothed_rtt);
        assert_eq!(decoded.min_rtt, status.min_rtt);
        assert_eq!(decoded.cwnd, status.cwnd);
    }

    #[test]
    fn test_secure_recovery_status_roundtrip_compressed() {
        let status = RecoveryStatus {
            bytes_sent: 1000,
            bytes_acked: 900,
            bytes_lost: 100,
            packets_in_flight: 5,
            probe_timeout_count: 1,
            smoothed_rtt: Some(Duration::from_millis(75)),
            min_rtt: Some(Duration::from_millis(33)),
            cwnd: 65535,
        };

        let (_meta, blob) = encode_secure_recovery_status(&status, CompressionAlgorithm::Gzip).unwrap();
        let (_decoded_meta, decoded) = decode_secure_recovery_status(&blob).unwrap();
        assert_eq!(decoded.bytes_sent, status.bytes_sent);
        assert_eq!(decoded.bytes_acked, status.bytes_acked);
        assert_eq!(decoded.bytes_lost, status.bytes_lost);
        assert_eq!(decoded.packets_in_flight, status.packets_in_flight);
        assert_eq!(decoded.probe_timeout_count, status.probe_timeout_count);
        assert_eq!(decoded.smoothed_rtt, status.smoothed_rtt);
        assert_eq!(decoded.min_rtt, status.min_rtt);
        assert_eq!(decoded.cwnd, status.cwnd);
    }

    #[test]
    fn test_secure_recovery_status_tamper_detection() {
        let status = RecoveryStatus {
            bytes_sent: 10,
            bytes_acked: 8,
            bytes_lost: 2,
            packets_in_flight: 1,
            probe_timeout_count: 0,
            smoothed_rtt: None,
            min_rtt: None,
            cwnd: 1200,
        };

        let (_meta, blob) =
            encode_secure_recovery_status(&status, CompressionAlgorithm::Identity).unwrap();

        let mut tampered = blob.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0xA5;
        }

        assert!(decode_secure_recovery_status(&tampered).is_err());
    }
}