use super::error::{Error, Result};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    Cubic,
    Reno,
    Bbr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    SlowStart,
    CongestionAvoidance,
    Recovery,
}

#[derive(Debug, Clone)]
struct CubicState {
    epoch_start: Option<Instant>,
    w_max: f64, // last loss event
    k: f64, // time to reach w_max
    w_cubic: f64, // origin point
    c: f64, // cubic scaling constant
    beta: f64, // multiplicative decrease factor
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
                return Ok(())
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
            let rtt_diff = if srtt > rtt {
                srtt - rtt
            } else {
                rtt - srtt
            };

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

    fn cubic_on_loss(&mut self, now: Instant) {
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
}