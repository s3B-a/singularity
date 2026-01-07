use super::packet::DnsPacket;
use super::record::RecordType;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use std::fmt::Write;

pub struct DnsQuery {
    pub id: u16,
    pub timeout: Duration,
    last_good_server: Option<SocketAddr>,
}

impl DnsQuery {
    pub fn new() -> Self {
        Self {
            id: Self::generate_id(),
            timeout: Duration::from_secs(5),
            last_good_server: None,
        }
    }

    fn generate_id() -> u16 {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};
        use std::time::SystemTime;

        let state = RandomState::new();
        let mut hasher = state.build_hasher();
        SystemTime::now().hash(&mut hasher);
        (hasher.finish() & 0xFFFF) as u16
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    pub fn query(&mut self, name: &str, record_type: RecordType, server: SocketAddr) -> io::Result<DnsPacket> {
        let packet = DnsPacket::new_query(self.id, name.to_string(), record_type);
        let data = packet.write()?;
        let socket = UdpSocket::bind("0.0.0.0:0")?;

        socket.set_read_timeout(Some(self.timeout))?;
        socket.set_write_timeout(Some(self.timeout))?;
        socket.send_to(&data, server)?;

        let mut buffer = vec![0u8; 512];
        let (size, _) = socket.recv_from(&mut buffer)?;
        buffer.truncate(size);

        let response = DnsPacket::read(&buffer)?;
        if response.header.id != self.id {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Response ID does not match query ID"));
        }

        self.id = self.id.wrapping_add(1);
        Ok(response)
    }

    pub fn query_with_retries(&mut self, name: &str, record_type: RecordType, servers: &[SocketAddr], retries: usize) -> io::Result<DnsPacket> {
        let mut last_error = None;
        if let Some(server) = self.last_good_server {
            if let Ok(resp) = self.query(name, record_type, server) {
                return Ok(resp);
            }
        }

        for _ in 0..retries {
            for &server in servers {
                match self.query(name, record_type, server) {
                    Ok(resp) => {
                        self.last_good_server = Some(server);
                        return Ok(resp);
                    }
                    Err(e) => last_error = Some(e),
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "No DNS servers available")
        }))
    }

    pub fn resolve_a(&mut self, name: &str, server: SocketAddr) -> io::Result<Vec<std::net::Ipv4Addr>> {
        let response = self.query(name, RecordType::A, server)?;
        
        let mut addresses = Vec::new();
        for answer in response.answers {
            if let super::record::RecordData::A(ip) = answer.data {
                addresses.push(ip);
            }
        }

        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No A records found",
            ));
        }

        Ok(addresses)
    }

    pub fn resolve_aaaa(&mut self, name: &str, server: SocketAddr) -> io::Result<Vec<std::net::Ipv6Addr>> {
        let response = self.query(name, RecordType::AAAA, server)?;
        
        let mut addresses = Vec::new();
        for answer in response.answers {
            if let super::record::RecordData::AAAA(ip) = answer.data {
                addresses.push(ip);
            }
        }

        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No AAAA records found",
            ));
        }

        Ok(addresses)
    }

    pub fn resolve_cname(&mut self, name: &str, server: SocketAddr) -> io::Result<String> {
        let response = self.query(name, RecordType::CNAME, server)?;
        
        for answer in response.answers {
            if let super::record::RecordData::CNAME(cname) = answer.data {
                return Ok(cname);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No CNAME record found",
        ))
    }

    pub fn resolve_mx(&mut self, name: &str, server: SocketAddr) -> io::Result<Vec<(u16, String)>> {
        let response = self.query(name, RecordType::MX, server)?;
        
        let mut mx_records = Vec::new();
        for answer in response.answers {
            if let super::record::RecordData::MX { preference, exchange } = answer.data {
                mx_records.push((preference, exchange));
            }
        }

        if mx_records.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No MX records found",
            ));
        }

        mx_records.sort_by_key(|(pref, _)| *pref);
        Ok(mx_records)
    }

    pub fn resolve_txt(&mut self, name: &str, server: SocketAddr) -> io::Result<Vec<Vec<String>>> {
        let response = self.query(name, RecordType::TXT, server)?;
        
        let mut txt_records = Vec::new();
        for answer in response.answers {
            if let super::record::RecordData::TXT(texts) = answer.data {
                txt_records.push(texts);
            }
        }

        if txt_records.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No TXT records found",
            ));
        }

        Ok(txt_records)
    }

    pub fn reverse_lookup(&mut self, ip: std::net::IpAddr, server: SocketAddr) -> io::Result<String> {
        let ptr_name = match ip {
            std::net::IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0])
            }
            std::net::IpAddr::V6(ipv6) => ipv6_ptr(ipv6),
        };

        let response = self.query(&ptr_name, RecordType::PTR, server)?;
        
        for answer in response.answers {
            if let super::record::RecordData::PTR(name) = answer.data {
                return Ok(name);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No PTR record found",
        ))
    }
}

impl Default for DnsQuery {
    fn default() -> Self {
        Self::new()
    }
}

fn ipv6_ptr(ipv6: std::net::Ipv6Addr) -> String {
    let segments = ipv6.segments();
    let mut s = String::with_capacity(32 * 2 + 9); // nibbles + dots + suffix

    for segment in segments.iter().rev() {
        for i in (0..4).rev() {
            let nibble = (segment >> (i * 4)) & 0xF;
            write!(s, "{:x}.", nibble).unwrap();
        }
    }

    s.push_str("ip6.arpa");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id() {
        let id1 = DnsQuery::generate_id();
        let id2 = DnsQuery::generate_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_query_creation() {
        let query = DnsQuery::new();
        assert_eq!(query.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_query_with_timeout() {
        let query = DnsQuery::new().with_timeout(Duration::from_secs(10));
        assert_eq!(query.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_query_with_id() {
        let query = DnsQuery::new().with_id(12345);
        assert_eq!(query.id, 12345);
    }

    #[test]
    fn test_reverse_lookup_ipv4_name() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        assert!(ip.is_ipv4());
    }

    #[test]
    fn test_reverse_lookup_ipv6_name() {
        let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x0db8, 0, 0, 0, 0, 0, 1,
        ));
        
        assert!(ip.is_ipv6());
    }
}