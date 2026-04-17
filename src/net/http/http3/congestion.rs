use super::error::Result;
use crate::crypto::constant_time_eq;
use crate::crypto::encoding::pem;
use crate::crypto::hash::hmac::hmac_sha256;
use crate::crypto::hash::sha2::sha256;
use crate::crypto::random;
use crate::net::http::compression::{self, CompressionAlgorithm, CompressionLevel};
use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CONGESTION_STATUS_BLOB_MAGIC: &str = "SINGULARITY_HTTP3_CONGESTION_STATUS_BLOB_V1";
const CONGESTION_STATUS_BLOB_CONTEXT: &str = "SINGULARITY_HTTP3_CONGESTION_STATUS_BLOB_BINDING_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureCongestionStatusBlobMeta {
    pub algorithm: CompressionAlgorithm,
    pub nonce_b64: String,
    pub digest_b64: String,
    pub tag_b64: String,
    pub raw_size: usize,
    pub encoded_size: usize,
    pub issued_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    Cubic,
    Reno,
    Bbr,
}

impl CongestionAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            CongestionAlgorithm::Cubic => "cubic",
            CongestionAlgorithm::Reno => "reno",
            CongestionAlgorithm::Bbr => "bbr",
        }
    }

    pub fn from_str(v: &str) -> io::Result<Self> {
        match v.trim() {
            "cubic" => Ok(CongestionAlgorithm::Cubic),
            "reno" => Ok(CongestionAlgorithm::Reno),
            "bbr" => Ok(CongestionAlgorithm::Bbr),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown congestion algorithm '{}'", other),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    SlowStart,
    CongestionAvoidance,
    Recovery,
}

impl CongestionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            CongestionState::SlowStart => "slow-start",
            CongestionState::CongestionAvoidance => "congestion-avoidance",
            CongestionState::Recovery => "recovery",
        }
    }

    pub fn from_str(v: &str) -> io::Result<Self> {
        match v.trim() {
            "slow-start" => Ok(CongestionState::SlowStart),
            "congestion-avoidance" => Ok(CongestionState::CongestionAvoidance),
            "recovery" => Ok(CongestionState::Recovery),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown congestion state '{}'", other),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CongestionStatus {
    pub algorithm: CongestionAlgorithm,
    pub cwnd: u64,
    pub ssthresh: u64,
    pub bytes_in_flight: u64,
    pub state: CongestionState,
    pub max_datagram_size: u64,
    pub min_cwnd: u64,
    pub max_cwnd: u64,
    pub initial_cwnd: u64,
    pub smoothed_rtt: Option<Duration>,
    pub rttvar: Duration,
    pub min_rtt: Option<Duration>,
    pub last_rtt: Option<Duration>,
    pub bytes_acked_since_increase: u64,
}

impl CongestionStatus {
    pub fn from_controller(controller: &CongestionController) -> Self {
        Self {
            algorithm: controller.algorithm,
            cwnd: controller.cwnd,
            ssthresh: controller.ssthresh,
            bytes_in_flight: controller.bytes_in_flight,
            state: controller.state,
            max_datagram_size: controller.max_datagram_size,
            min_cwnd: controller.min_cwnd,
            max_cwnd: controller.max_cwnd,
            initial_cwnd: controller.initial_cwnd,
            smoothed_rtt: controller.smoothed_rtt,
            rttvar: controller.rttvar,
            min_rtt: controller.min_rtt,
            last_rtt: controller.last_rtt,
            bytes_acked_since_increase: controller.bytes_acked_since_increase,
        }
    }

    pub fn to_controller(&self) -> CongestionController {
        let mut controller = CongestionController::new(self.algorithm, self.max_datagram_size.max(1));
        controller.restore_from_snapshot(self);
        controller
    }

    pub fn to_secure_blob(&self, algorithm: CompressionAlgorithm) -> io::Result<(SecureCongestionStatusBlobMeta, Vec<u8>)> {
        let mut selected_algorithm = algorithm;
        if !selected_algorithm.is_implemented() {
            selected_algorithm = CompressionAlgorithm::Identity;
        }

        let raw_payload = serialize_congestion_status(self);
        let encoded_payload = if selected_algorithm == CompressionAlgorithm::Identity {
            raw_payload.clone()
        } else {
            compression::compress(selected_algorithm, &raw_payload, CompressionLevel::Default)?
        };

        let nonce = random::generate_random(24).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate secure congestion-status nonce: {}", e),
            )
        })?;

        let digest = sha256(&raw_payload);
        let tag = compute_congestion_status_blob_tag(
            &nonce,
            selected_algorithm,
            raw_payload.len(),
            &encoded_payload,
        );

        let meta = SecureCongestionStatusBlobMeta {
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
            magic = CONGESTION_STATUS_BLOB_MAGIC,
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

    pub fn to_secure_blob_auto(&self, accept_encoding: &str) -> io::Result<(SecureCongestionStatusBlobMeta, Vec<u8>)> {
        self.to_secure_blob(select_secure_congestion_status_algorithm(accept_encoding))
    }

    pub fn from_secure_blob(data: &[u8]) -> io::Result<(SecureCongestionStatusBlobMeta, Self)> {
        let (header, body) = split_header_body(data)?;
        let meta = parse_secure_congestion_status_meta(&header, body.len())?;
        let nonce = pem::decode(&meta.nonce_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid congestion-status nonce encoding: {}", e),
            )
        })?;

        let digest = pem::decode(&meta.digest_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid congestion-status digest encoding: {}", e),
            )
        })?;

        let tag = pem::decode(&meta.tag_b64).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid congestion-status tag encoding: {}", e),
            )
        })?;

        if digest.len() != 32 || tag.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "congestion-status digest or tag has invalid length",
            ));
        }

        let expected_tag =
            compute_congestion_status_blob_tag(&nonce, meta.algorithm, meta.raw_size, body);

        if !constant_time_eq(&expected_tag, &tag) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure congestion-status blob tag verification failed",
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
                    "congestion-status raw-size mismatch: expected {}, got {}",
                    meta.raw_size,
                    raw_payload.len()
                ),
            ));
        }

        let computed_digest = sha256(&raw_payload);
        if !constant_time_eq(&computed_digest, &digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure congestion-status blob digest verification failed",
            ));
        }

        let status = deserialize_congestion_status(&raw_payload)?;
        Ok((meta, status))
    }
}

#[derive(Debug, Clone)]
struct CubicState {
    epoch_start: Option<Instant>,
    w_max: f64,
    k: f64,
    w_cubic: f64,
    c: f64,
    beta: f64,
}

#[derive(Debug, Clone)]
struct BbrState {
    max_bandwidth: u64,
    min_rtt: Duration,
    pacing_rate: u64,
    mode: BbrMode,
    cycle_index: usize,
    cycle_start: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BbrMode {
    Startup,
    Drain,
    ProbeBW,
    ProbeRTT,
}

pub struct CongestionController {
    algorithm: CongestionAlgorithm,
    cwnd: u64,
    ssthresh: u64,
    bytes_in_flight: u64,
    state: CongestionState,
    max_datagram_size: u64,
    min_cwnd: u64,
    max_cwnd: u64,
    initial_cwnd: u64,
    smoothed_rtt: Option<Duration>,
    rttvar: Duration,
    min_rtt: Option<Duration>,
    last_rtt: Option<Duration>,
    last_congestion_time: Option<Instant>,
    recovery_start_time: Option<Instant>,
    bytes_acked_since_increase: u64,
    cubic: CubicState,
    bbr: BbrState,
}

impl CongestionController {
    pub fn new(algorithm: CongestionAlgorithm, max_datagram_size: u64) -> Self {
        let initial_cwnd = 10 * max_datagram_size;
        Self {
            algorithm,
            cwnd: initial_cwnd,
            ssthresh: u64::MAX,
            bytes_in_flight: 0,
            state: CongestionState::SlowStart,
            max_datagram_size,
            min_cwnd: 2 * max_datagram_size,
            max_cwnd: 1000 * max_datagram_size,
            initial_cwnd,
            smoothed_rtt: None,
            rttvar: Duration::from_millis(0),
            min_rtt: None,
            last_rtt: None,
            last_congestion_time: None,
            recovery_start_time: None,
            bytes_acked_since_increase: 0,
            cubic: CubicState::default(),
            bbr: BbrState::default(),
        }
    }

    pub fn cwnd(&self) -> u64 {
        self.cwnd
    }

    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    pub fn can_send(&self) -> bool {
        self.bytes_in_flight < self.cwnd
    }

    pub fn available_window(&self) -> u64 {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }

    pub fn on_packet_sent(&mut self, bytes: u64) {
        self.bytes_in_flight += bytes;
    }

    pub fn on_packet_acked(&mut self, bytes: u64, rtt: Duration, now: Instant) -> Result<()> {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        self.update_rtt(rtt);
        match self.algorithm {
            CongestionAlgorithm::Cubic => self.cubic_on_acked(bytes, now),
            CongestionAlgorithm::Reno => self.reno_on_acked(bytes),
            CongestionAlgorithm::Bbr => self.bbr_on_acked(bytes, now),
        }

        Ok(())
    }

    pub fn on_congestion_event(&mut self, now: Instant) -> Result<()> {
        if let Some(recovery_start) = self.recovery_start_time {
            if now < recovery_start {
                return Ok(());
            }
        }

        self.last_congestion_time = Some(now);
        self.recovery_start_time = Some(now);
        match self.algorithm {
            CongestionAlgorithm::Cubic => self.cubic_on_loss(now),
            CongestionAlgorithm::Reno => self.reno_on_loss(),
            CongestionAlgorithm::Bbr => self.bbr_on_loss(now),
        }

        Ok(())
    }

    fn update_rtt(&mut self, rtt: Duration) {
        self.last_rtt = Some(rtt);
        self.min_rtt = Some(self.min_rtt.map_or(rtt, |min| min.min(rtt)));
        if let Some(srtt) = self.smoothed_rtt {
            let rtt_diff = if srtt > rtt { srtt - rtt } else { rtt - srtt };

            self.rttvar = (self.rttvar * 3 + rtt_diff) / 4;
            self.smoothed_rtt = Some((srtt * 7 + rtt) / 8);
        } else {
            self.smoothed_rtt = Some(rtt);
            self.rttvar = rtt / 2;
        }
    }

    fn cubic_on_acked(&mut self, bytes_acked: u64, now: Instant) {
        if self.state == CongestionState::Recovery {
            return;
        }

        if self.state == CongestionState::SlowStart {
            self.cwnd += bytes_acked;
            if self.cwnd >= self.ssthresh {
                self.state = CongestionState::CongestionAvoidance;
            }
        } else {
            self.cubic_update(now);
        }

        self.cwnd = self.cwnd.min(self.max_cwnd);
    }

    fn cubic_update(&mut self, now: Instant) {
        if self.cubic.epoch_start.is_none() {
            self.cubic.epoch_start = Some(now);
            self.cubic.w_cubic = self.cwnd as f64 / self.max_datagram_size as f64;
            self.cubic.k = ((self.cubic.w_max * (1.0 - self.cubic.beta)) / self.cubic.c).cbrt();
        }

        let t = now.duration_since(self.cubic.epoch_start.unwrap()).as_secs_f64();
        let offset = t - self.cubic.k;
        let cubic_cwnd = self.cubic.c * offset.powi(3) + self.cubic.w_max;
        let tcp_cwnd = self.cubic.w_max * (1.0 + 0.5 * t);
        let target = cubic_cwnd.max(tcp_cwnd) * self.max_datagram_size as f64;
        if target > self.cwnd as f64 {
            self.bytes_acked_since_increase += 1;
            if self.bytes_acked_since_increase >= self.cwnd {
                self.cwnd += self.max_datagram_size;
                self.bytes_acked_since_increase = 0;
            }
        }
    }

    fn cubic_on_loss(&mut self, _now: Instant) {
        self.cubic.epoch_start = None;
        self.cubic.w_max = self.cwnd as f64 / self.max_datagram_size as f64;
        self.cwnd = (self.cwnd as f64 * self.cubic.beta) as u64;
        self.cwnd = self.cwnd.max(self.min_cwnd);
        self.ssthresh = self.cwnd;
        self.state = CongestionState::Recovery;
    }

    fn reno_on_acked(&mut self, bytes_acked: u64) {
        if self.state == CongestionState::Recovery {
            return;
        }

        if self.state == CongestionState::SlowStart {
            self.cwnd += bytes_acked;
            if self.cwnd >= self.ssthresh {
                self.state = CongestionState::CongestionAvoidance;
            }
        } else {
            self.bytes_acked_since_increase += bytes_acked;
            if self.bytes_acked_since_increase >= self.cwnd {
                self.cwnd += self.max_datagram_size;
                self.bytes_acked_since_increase = 0;
            }
        }

        self.cwnd = self.cwnd.min(self.max_cwnd);
    }

    fn reno_on_loss(&mut self) {
        self.ssthresh = self.cwnd / 2;
        self.ssthresh = self.ssthresh.max(self.min_cwnd);
        self.cwnd = self.ssthresh;
        self.state = CongestionState::Recovery;
        self.bytes_acked_since_increase = 0;
    }

    fn bbr_on_acked(&mut self, bytes_acked: u64, now: Instant) {
        if let Some(rtt) = self.last_rtt {
            let bandwidth = (bytes_acked as f64 / rtt.as_secs_f64()) as u64;
            self.bbr.max_bandwidth = self.bbr.max_bandwidth.max(bandwidth);
        }

        match self.bbr.mode {
            BbrMode::Startup => {
                self.cwnd += bytes_acked;
                if self.bbr.max_bandwidth > 0 {
                    if self.cwnd > self.bbr.max_bandwidth * 2 {
                        self.bbr.mode = BbrMode::Drain;
                    }
                }
            }
            BbrMode::Drain => {
                let bdp = self.bbr.max_bandwidth * self.bbr.min_rtt.as_secs_f64() as u64;
                if self.bytes_in_flight <= bdp {
                    self.bbr.mode = BbrMode::ProbeBW;
                    self.bbr.cycle_start = Some(now);
                }
            }
            BbrMode::ProbeBW => {
                let bdp = self.bbr.max_bandwidth * self.bbr.min_rtt.as_secs_f64() as u64;
                self.cwnd = bdp;
                if now.duration_since(self.bbr.cycle_start.unwrap()) > self.bbr.min_rtt {
                    self.bbr.cycle_index = (self.bbr.cycle_index + 1) % 8;
                    self.bbr.cycle_start = Some(now);
                }
            }
            BbrMode::ProbeRTT => {
                self.cwnd = self.min_cwnd;
                if now.duration_since(self.bbr.cycle_start.unwrap()) > Duration::from_millis(200) {
                    self.bbr.mode = BbrMode::ProbeBW;
                    self.bbr.cycle_start = Some(now);
                }
            }
        }

        self.cwnd = self.cwnd.max(self.min_cwnd).min(self.max_cwnd);
    }

    fn bbr_on_loss(&mut self, now: Instant) {
        self.bbr.mode = BbrMode::ProbeRTT;
        self.bbr.cycle_start = Some(now);
    }

    pub fn smoothed_rtt(&self) -> Option<Duration> {
        self.smoothed_rtt
    }

    pub fn rttvar(&self) -> Duration {
        self.rttvar
    }

    pub fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt
    }

    pub fn last_rtt(&self) -> Option<Duration> {
        self.last_rtt
    }

    pub fn exit_recovery(&mut self) {
        if self.state == CongestionState::Recovery {
            self.state = CongestionState::CongestionAvoidance;
            self.recovery_start_time = None;
        }
    }

    pub fn in_recovery(&self) -> bool {
        self.state == CongestionState::Recovery
    }

    pub fn reset(&mut self) {
        self.cwnd = self.initial_cwnd;
        self.ssthresh = u64::MAX;
        self.bytes_in_flight = 0;
        self.state = CongestionState::SlowStart;
        self.smoothed_rtt = None;
        self.rttvar = Duration::from_millis(0);
        self.min_rtt = None;
        self.last_rtt = None;
        self.last_congestion_time = None;
        self.recovery_start_time = None;
        self.bytes_acked_since_increase = 0;
        self.cubic = CubicState::default();
        self.bbr = BbrState::default();
    }

    pub fn state(&self) -> CongestionState {
        self.state
    }

    pub fn ssthresh(&self) -> u64 {
        self.ssthresh
    }

    pub fn on_probe_timeout(&mut self, now: Instant) {
        if self.algorithm == CongestionAlgorithm::Bbr {
            self.bbr.mode = BbrMode::ProbeRTT;
            self.bbr.cycle_start = Some(now);
        }
    }

    pub fn snapshot(&self) -> CongestionStatus {
        CongestionStatus::from_controller(self)
    }

    pub fn restore_from_snapshot(&mut self, status: &CongestionStatus) {
        let max_datagram_size = status.max_datagram_size.max(1);
        let default_min_cwnd = 2 * max_datagram_size;

        self.algorithm = status.algorithm;
        self.max_datagram_size = max_datagram_size;
        self.min_cwnd = status.min_cwnd.max(default_min_cwnd);
        self.max_cwnd = status.max_cwnd.max(self.min_cwnd);
        self.initial_cwnd = status.initial_cwnd.clamp(self.min_cwnd, self.max_cwnd);
        self.cwnd = status.cwnd.clamp(self.min_cwnd, self.max_cwnd);
        self.ssthresh = status.ssthresh.max(self.min_cwnd);
        self.bytes_in_flight = status.bytes_in_flight.min(self.cwnd);
        self.state = status.state;
        self.smoothed_rtt = status.smoothed_rtt;
        self.rttvar = status.rttvar;
        self.min_rtt = status.min_rtt;
        self.last_rtt = status.last_rtt;
        self.bytes_acked_since_increase = status.bytes_acked_since_increase;
        self.last_congestion_time = None;
        self.recovery_start_time = None;
        self.cubic = CubicState::default();
        self.bbr = BbrState::default();
        if let Some(min_rtt) = self.min_rtt {
            self.bbr.min_rtt = min_rtt;
        }
    }
}

pub fn select_secure_congestion_status_algorithm(accept_encoding: &str) -> CompressionAlgorithm {
    let accepted = compression::parse_accept_encoding(accept_encoding);
    for (algorithm, quality) in accepted {
        if quality > 0.0 && algorithm.is_implemented() && algorithm != CompressionAlgorithm::Identity {
            return algorithm;
        }
    }

    CompressionAlgorithm::Identity
}

pub fn encode_secure_congestion_status(status: &CongestionStatus, algorithm: CompressionAlgorithm) -> io::Result<(SecureCongestionStatusBlobMeta, Vec<u8>)> {
    status.to_secure_blob(algorithm)
}

pub fn encode_secure_congestion_status_auto(status: &CongestionStatus, accept_encoding: &str) -> io::Result<(SecureCongestionStatusBlobMeta, Vec<u8>)> {
    status.to_secure_blob_auto(accept_encoding)
}

pub fn decode_secure_congestion_status(data: &[u8]) -> io::Result<(SecureCongestionStatusBlobMeta, CongestionStatus)> {
    CongestionStatus::from_secure_blob(data)
}

fn serialize_congestion_status(status: &CongestionStatus) -> Vec<u8> {
    format!(
        "algorithm={}\ncwnd={}\nssthresh={}\nbytes-in-flight={}\nstate={}\nmax-datagram-size={}\nmin-cwnd={}\nmax-cwnd={}\ninitial-cwnd={}\nsmoothed-rtt-ms={}\nrttvar-ms={}\nmin-rtt-ms={}\nlast-rtt-ms={}\nbytes-acked-since-increase={}\n",
        status.algorithm.as_str(),
        status.cwnd,
        status.ssthresh,
        status.bytes_in_flight,
        status.state.as_str(),
        status.max_datagram_size,
        status.min_cwnd,
        status.max_cwnd,
        status.initial_cwnd,
        opt_duration_ms_to_text(status.smoothed_rtt),
        status.rttvar.as_millis(),
        opt_duration_ms_to_text(status.min_rtt),
        opt_duration_ms_to_text(status.last_rtt),
        status.bytes_acked_since_increase,
    )
    .into_bytes()
}

fn deserialize_congestion_status(raw_payload: &[u8]) -> io::Result<CongestionStatus> {
    let payload = std::str::from_utf8(raw_payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "congestion-status payload is not valid utf-8",
        )
    })?;

    let mut map = HashMap::new();
    for line in payload.lines() {
        let (key, value) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid congestion-status payload line '{}'", line),
            )
        })?;

        map.insert(key.trim().to_string(), value.trim().to_string());
    }

    let parse_u64 = |key: &str| -> io::Result<u64> {
        map.get(key).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing '{}' in congestion-status payload", key),
            )
        })?.parse::<u64>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid '{}' in congestion-status payload", key),
            )
        })
    };

    let algorithm = CongestionAlgorithm::from_str(
        map.get("algorithm").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing algorithm in congestion-status payload",
            )
        })?,
    )?;

    let state = CongestionState::from_str(
        map.get("state").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing state in congestion-status payload",
            )
        })?,
    )?;

    let smoothed_rtt = parse_opt_duration_ms(
        map.get("smoothed-rtt-ms").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing smoothed-rtt-ms in congestion-status payload",
            )
        })?,
    )?;
    let min_rtt = parse_opt_duration_ms(
        map.get("min-rtt-ms").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing min-rtt-ms in congestion-status payload",
            )
        })?,
    )?;
    let last_rtt = parse_opt_duration_ms(
        map.get("last-rtt-ms").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing last-rtt-ms in congestion-status payload",
            )
        })?,
    )?;

    let rttvar_ms = parse_u64("rttvar-ms")?;

    Ok(CongestionStatus {
        algorithm,
        cwnd: parse_u64("cwnd")?,
        ssthresh: parse_u64("ssthresh")?,
        bytes_in_flight: parse_u64("bytes-in-flight")?,
        state,
        max_datagram_size: parse_u64("max-datagram-size")?,
        min_cwnd: parse_u64("min-cwnd")?,
        max_cwnd: parse_u64("max-cwnd")?,
        initial_cwnd: parse_u64("initial-cwnd")?,
        smoothed_rtt,
        rttvar: Duration::from_millis(rttvar_ms),
        min_rtt,
        last_rtt,
        bytes_acked_since_increase: parse_u64("bytes-acked-since-increase")?,
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

fn compute_congestion_status_blob_tag(nonce: &[u8], algorithm: CompressionAlgorithm, raw_size: usize, encoded_payload: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(CONGESTION_STATUS_BLOB_CONTEXT.as_bytes());
    mac_input.extend_from_slice(algorithm.content_encoding().as_bytes());
    mac_input.extend_from_slice(&(raw_size as u64).to_be_bytes());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(encoded_payload);
    hmac_sha256(CONGESTION_STATUS_BLOB_CONTEXT.as_bytes(), &mac_input)
}

fn split_header_body(data: &[u8]) -> io::Result<(String, &[u8])> {
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "congestion-status header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 2..]));
    }

    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&data[..pos]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "congestion-status header is not valid utf-8",
            )
        })?;

        return Ok((header.to_string(), &data[pos + 4..]));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "congestion-status blob missing header/body separator",
    ))
}

fn parse_secure_congestion_status_meta(header: &str, body_len: usize) -> io::Result<SecureCongestionStatusBlobMeta> {
    let mut lines = header.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != CONGESTION_STATUS_BLOB_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid secure congestion-status blob magic",
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
                format!("invalid secure congestion-status header line '{}'", line),
            )
        })?;

        match k.trim() {
            "content-encoding" => {
                algorithm = CompressionAlgorithm::from_content_encoding(v.trim()).ok_or_else(
                    || {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported content-encoding '{}'", v.trim()),
                        )
                    },
                )?;
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
                        "invalid raw-size in congestion-status blob",
                    )
                })?);
            }
            "encoded-size" => {
                encoded_size = Some(v.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid encoded-size in congestion-status blob",
                    )
                })?);
            }
            "issued-at" => {
                issued_at_unix = Some(v.trim().parse::<u64>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid issued-at in congestion-status blob",
                    )
                })?);
            }
            _ => {}
        }
    }

    let meta = SecureCongestionStatusBlobMeta {
        algorithm,
        nonce_b64: nonce_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing nonce in secure congestion-status blob header",
            )
        })?,
        digest_b64: digest_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing digest in secure congestion-status blob header",
            )
        })?,
        tag_b64: tag_b64.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing tag in secure congestion-status blob header",
            )
        })?,
        raw_size: raw_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing raw-size in secure congestion-status blob header",
            )
        })?,
        encoded_size: encoded_size.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing encoded-size in secure congestion-status blob header",
            )
        })?,
        issued_at_unix: issued_at_unix.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing issued-at in secure congestion-status blob header",
            )
        })?,
    };

    if meta.encoded_size != body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "congestion-status encoded-size mismatch: expected {}, got {}",
                meta.encoded_size, body_len
            ),
        ));
    }

    Ok(meta)
}

impl Default for CubicState {
    fn default() -> Self {
        Self {
            epoch_start: None,
            w_max: 0.0,
            k: 0.0,
            w_cubic: 0.0,
            c: 0.4,
            beta: 0.7,
        }
    }
}

impl Default for BbrState {
    fn default() -> Self {
        Self {
            max_bandwidth: 0,
            min_rtt: Duration::from_millis(10),
            pacing_rate: 0,
            mode: BbrMode::Startup,
            cycle_index: 0,
            cycle_start: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_congestion_controller_creation() {
        let cc = CongestionController::new(CongestionAlgorithm::Cubic, 1200);
        assert_eq!(cc.cwnd(), 12000);
        assert_eq!(cc.bytes_in_flight(), 0);
        assert!(cc.can_send());
    }

    #[test]
    fn test_packet_sent() {
        let mut cc = CongestionController::new(CongestionAlgorithm::Cubic, 1200);
        cc.on_packet_sent(1200);
        assert_eq!(cc.bytes_in_flight(), 1200);
        assert!(cc.can_send());
    }

    #[test]
    fn test_window_exhaustion() {
        let mut cc = CongestionController::new(CongestionAlgorithm::Cubic, 1200);
        let cwnd = cc.cwnd();
        
        cc.on_packet_sent(cwnd);
        assert_eq!(cc.bytes_in_flight(), cwnd);
        assert!(!cc.can_send());
    }

    #[test]
    fn test_packet_acked() {
        let mut cc = CongestionController::new(CongestionAlgorithm::Cubic, 1200);
        cc.on_packet_sent(1200);
        
        cc.on_packet_acked(1200, Duration::from_millis(50), Instant::now()).unwrap();
        assert_eq!(cc.bytes_in_flight(), 0);
        assert!(cc.can_send());
    }

    #[test]
    fn test_slow_start_growth() {
        let mut cc = CongestionController::new(CongestionAlgorithm::Reno, 1200);
        let initial_cwnd = cc.cwnd();
        
        cc.on_packet_acked(1200, Duration::from_millis(50), Instant::now()).unwrap();
        assert!(cc.cwnd() > initial_cwnd);
        assert_eq!(cc.state(), CongestionState::SlowStart);
    }

    #[test]
    fn test_congestion_event() {
        let mut cc = CongestionController::new(CongestionAlgorithm::Reno, 1200);
        let initial_cwnd = cc.cwnd();
        
        cc.on_congestion_event(Instant::now()).unwrap();
        assert!(cc.cwnd() < initial_cwnd);
        assert!(cc.in_recovery());
    }

    #[test]
    fn test_rtt_update() {
        let mut cc = CongestionController::new(CongestionAlgorithm::Cubic, 1200);
        
        let rtt1 = Duration::from_millis(50);
        cc.update_rtt(rtt1);
        assert_eq!(cc.smoothed_rtt(), Some(rtt1));
        assert_eq!(cc.min_rtt(), Some(rtt1));
        
        let rtt2 = Duration::from_millis(60);
        cc.update_rtt(rtt2);
        assert!(cc.smoothed_rtt().is_some());
        assert_eq!(cc.min_rtt(), Some(rtt1));
    }

    #[test]
    fn test_different_algorithms() {
        let cc_cubic = CongestionController::new(CongestionAlgorithm::Cubic, 1200);
        let cc_reno = CongestionController::new(CongestionAlgorithm::Reno, 1200);
        let cc_bbr = CongestionController::new(CongestionAlgorithm::Bbr, 1200);
        
        assert_eq!(cc_cubic.cwnd(), cc_reno.cwnd());
        assert_eq!(cc_reno.cwnd(), cc_bbr.cwnd());
    }

    #[test]
    fn test_cwnd_limits() {
        let mut cc = CongestionController::new(CongestionAlgorithm::Reno, 1200);
        for _ in 0..10000 {
            cc.on_packet_acked(1200, Duration::from_millis(10), Instant::now()).unwrap();
        }

        assert!(cc.cwnd() <= cc.max_cwnd);
    }

    #[test]
    fn test_reset() {
        let mut cc = CongestionController::new(CongestionAlgorithm::Cubic, 1200);
        let initial_cwnd = cc.cwnd();
        
        cc.on_packet_sent(5000);
        cc.on_congestion_event(Instant::now()).unwrap();
        
        cc.reset();
        assert_eq!(cc.cwnd(), initial_cwnd);
        assert_eq!(cc.bytes_in_flight(), 0);
        assert_eq!(cc.state(), CongestionState::SlowStart);
    }

    #[test]
    fn test_exit_recovery() {
        let mut cc = CongestionController::new(CongestionAlgorithm::Reno, 1200);
        
        cc.on_congestion_event(Instant::now()).unwrap();
        assert!(cc.in_recovery());
        
        cc.exit_recovery();
        assert!(!cc.in_recovery());
        assert_eq!(cc.state(), CongestionState::CongestionAvoidance);
    }

    #[test]
    fn test_available_window() {
        let mut cc = CongestionController::new(CongestionAlgorithm::Cubic, 1200);
        let cwnd = cc.cwnd();
        
        assert_eq!(cc.available_window(), cwnd);
        
        cc.on_packet_sent(1000);
        assert_eq!(cc.available_window(), cwnd - 1000);
    }

    #[test]
    fn test_snapshot_and_restore() {
        let mut cc = CongestionController::new(CongestionAlgorithm::Reno, 1200);
        cc.on_packet_sent(2400);
        cc.on_packet_acked(1200, Duration::from_millis(40), Instant::now()).unwrap();

        let snapshot = cc.snapshot();
        let mut restored = CongestionController::new(CongestionAlgorithm::Bbr, 1400);
        restored.restore_from_snapshot(&snapshot);

        assert_eq!(restored.cwnd(), snapshot.cwnd);
        assert_eq!(restored.bytes_in_flight(), snapshot.bytes_in_flight);
        assert_eq!(restored.state(), snapshot.state);
        assert_eq!(restored.ssthresh(), snapshot.ssthresh);
        assert_eq!(restored.smoothed_rtt(), snapshot.smoothed_rtt);
    }

    #[test]
    fn test_secure_congestion_status_roundtrip_identity() {
        let status = CongestionStatus {
            algorithm: CongestionAlgorithm::Cubic,
            cwnd: 12000,
            ssthresh: 9000,
            bytes_in_flight: 3400,
            state: CongestionState::CongestionAvoidance,
            max_datagram_size: 1200,
            min_cwnd: 2400,
            max_cwnd: 1_200_000,
            initial_cwnd: 12000,
            smoothed_rtt: Some(Duration::from_millis(45)),
            rttvar: Duration::from_millis(10),
            min_rtt: Some(Duration::from_millis(20)),
            last_rtt: Some(Duration::from_millis(50)),
            bytes_acked_since_increase: 777,
        };

        let (meta, blob) = encode_secure_congestion_status(&status, CompressionAlgorithm::Identity).unwrap();
        assert_eq!(meta.algorithm, CompressionAlgorithm::Identity);

        let (_decoded_meta, decoded) = decode_secure_congestion_status(&blob).unwrap();
        assert_eq!(decoded, status);
    }

    #[test]
    fn test_secure_congestion_status_roundtrip_compressed() {
        let status = CongestionStatus {
            algorithm: CongestionAlgorithm::Bbr,
            cwnd: 65535,
            ssthresh: 32768,
            bytes_in_flight: 2048,
            state: CongestionState::Recovery,
            max_datagram_size: 1250,
            min_cwnd: 2500,
            max_cwnd: 1_250_000,
            initial_cwnd: 12500,
            smoothed_rtt: Some(Duration::from_millis(72)),
            rttvar: Duration::from_millis(15),
            min_rtt: Some(Duration::from_millis(30)),
            last_rtt: Some(Duration::from_millis(90)),
            bytes_acked_since_increase: 1234,
        };

        let (_meta, blob) =
            encode_secure_congestion_status(&status, CompressionAlgorithm::Gzip).unwrap();
        let (_decoded_meta, decoded) = decode_secure_congestion_status(&blob).unwrap();
        assert_eq!(decoded, status);
    }

    #[test]
    fn test_secure_congestion_status_tamper_detection() {
        let status = CongestionStatus {
            algorithm: CongestionAlgorithm::Reno,
            cwnd: 10000,
            ssthresh: 8000,
            bytes_in_flight: 1000,
            state: CongestionState::SlowStart,
            max_datagram_size: 1200,
            min_cwnd: 2400,
            max_cwnd: 1_200_000,
            initial_cwnd: 12000,
            smoothed_rtt: None,
            rttvar: Duration::from_millis(0),
            min_rtt: None,
            last_rtt: None,
            bytes_acked_since_increase: 0,
        };

        let (_meta, blob) = encode_secure_congestion_status(&status, CompressionAlgorithm::Identity).unwrap();
        let mut tampered = blob.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0x5A;
        }

        assert!(decode_secure_congestion_status(&tampered).is_err());
    }
}