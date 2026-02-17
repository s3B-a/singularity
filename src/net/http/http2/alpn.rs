use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlpnProtocol {
    Http2,
    Http11,
    Http10,
    Http3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NpnProtocol {
    Http2,
    Http11,
}

#[derive(Debug, Clone)]
pub struct AlpnNegotiator {
    supported_protocols: Vec<AlpnProtocol>,
    selected_protocol: Option<AlpnProtocol>,
    server_preference: bool,
}

#[derive(Debug, Clone)]
pub struct NpnNegotiator {
    supported_protocols: Vec<NpnProtocol>,
    selected_protocol: Option<NpnProtocol>,
}

impl AlpnProtocol {
    pub fn wire_format(&self) -> &'static [u8] {
        match self {
            AlpnProtocol::Http2 => b"h2",
            AlpnProtocol::Http11 => b"http/1.1",
            AlpnProtocol::Http10 => b"http/1.0",
            AlpnProtocol::Http3 => b"h3",
        }
    }

    pub fn from_wire(data: &[u8]) -> Option<Self> {
        match data {
            b"h2" => Some(AlpnProtocol::Http2),
            b"http/1.1" => Some(AlpnProtocol::Http11),
            b"http/1.0" => Some(AlpnProtocol::Http10),
            b"h3" => Some(AlpnProtocol::Http3),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AlpnProtocol::Http2 => "HTTP/2",
            AlpnProtocol::Http11 => "HTTP/1.1",
            AlpnProtocol::Http10 => "HTTP/1.0",
            AlpnProtocol::Http3 => "HTTP/3",
        }
    }

    pub fn supports_push(&self) -> bool {
        matches!(self, AlpnProtocol::Http2 | AlpnProtocol::Http3)
    }

    pub fn requires_tls(&self) -> bool {
        matches!(self, AlpnProtocol::Http2 | AlpnProtocol::Http3)
    }

    pub fn priority(&self) -> u8 {
        match self {
            AlpnProtocol::Http3 => 100,
            AlpnProtocol::Http2 => 90,
            AlpnProtocol::Http11 => 50,
            AlpnProtocol::Http10 => 10,
        }
    }
}

impl AlpnNegotiator {
    pub fn new() -> Self {
        Self {
            supported_protocols: vec![
                AlpnProtocol::Http2,
                AlpnProtocol::Http11,
            ],
            selected_protocol: None,
            server_preference: true,
        }
    }

    pub fn with_protocols(protocols: Vec<AlpnProtocol>) -> Self {
        let mut negotiator = Self::new();
        negotiator.supported_protocols = protocols;

        negotiator
    }

    pub fn set_server_preference(&mut self, enabled: bool) {
        self.server_preference = enabled;
    }

    pub fn add_protocol(&mut self, protocol: AlpnProtocol) {
        if !self.supported_protocols.contains(&protocol) {
            self.supported_protocols.push(protocol);
            self.sort_protocols();
        }
    }

    pub fn remove_protocol(&mut self, protocol: AlpnProtocol) {
        self.supported_protocols.retain(|&p| p != protocol);
    }

    pub fn supported_protocols_wire(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for protocol in &self.supported_protocols {
            let wire = protocol.wire_format();
            result.push(wire.len() as u8);
            result.extend_from_slice(wire);
        }

        result
    }

    pub fn negotiate(&mut self, client_protocols: &[u8]) -> Result<AlpnProtocol, String> {
        let client_prefs = Self::parse_protocol_list(client_protocols)
            .ok_or_else(|| "Failed to parse client ALPN protocols".to_string())?;

        if client_prefs.is_empty() {
            return Err("Client provided no ALPN protocols".to_string());
        }

        let selected = if self.server_preference {
            self.select_with_server_preference(&client_prefs)
        } else {
            self.select_with_client_preference(&client_prefs)
        };

        self.selected_protocol = selected;

        selected.ok_or_else(|| {
            let server_protos: Vec<&str> = self.supported_protocols
                .iter()
                .map(|p| p.name())
                .collect();
            let client_protos: Vec<&str> = client_prefs
                .iter()
                .map(|p| p.name())
                .collect();
            
            format!(
                "No common ALPN protocols. Server: {:?}, Client: {:?}",
                server_protos, client_protos
            )
        })
    }

    fn parse_protocol_list(data: &[u8]) -> Option<Vec<AlpnProtocol>> {
        let mut protocols = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            if pos >= data.len() {
                return None;
            }

            let len = data[pos] as usize;
            pos += 1;
            if pos + len > data.len() {
                return None;
            }

            if let Some(protocol) = AlpnProtocol::from_wire(&data[pos..pos + len]) {
                protocols.push(protocol);
            }

            pos += len;
        }

        if protocols.is_empty() {
            None
        } else {
            Some(protocols)
        }
    }

    fn select_with_server_preference(&self, client_prefs: &[AlpnProtocol]) -> Option<AlpnProtocol> {
        for &server_proto in &self.supported_protocols {
            if client_prefs.contains(&server_proto) {
                return Some(server_proto);
            }
        }

        None
    }

    fn select_with_client_preference(&self, client_prefs: &[AlpnProtocol]) -> Option<AlpnProtocol> {
        for &client_proto in client_prefs {
            if self.supported_protocols.contains(&client_proto) {
                return Some(client_proto);
            }
        }

        None
    }

    pub fn selected(&self) -> Option<AlpnProtocol> {
        self.selected_protocol
    }

    pub fn selected_wire(&self) -> Option<&'static [u8]> {
        self.selected_protocol.map(|p| p.wire_format())
    }

    pub fn is_negotiated(&self) -> bool {
        self.selected_protocol.is_some()
    }

    fn sort_protocols(&mut self) {
        self.supported_protocols.sort_by(|a, b| b.priority().cmp(&a.priority()));
    }

    pub fn supported_protocols_sorted(&self) -> Vec<AlpnProtocol> {
        let mut protocols = self.supported_protocols.clone();
        protocols.sort_by(|a, b| b.priority().cmp(&a.priority()));
        
        protocols
    }

    pub fn reset(&mut self) {
        self.selected_protocol = None;
    }
}

impl NpnProtocol {
    pub fn wire_format(&self) -> &'static [u8] {
        match self {
            NpnProtocol::Http2 => b"h2",
            NpnProtocol::Http11 => b"http/1.1",
        }
    }

    pub fn from_wire(data: &[u8]) -> Option<Self> {
        match data {
            b"h2" => Some(NpnProtocol::Http2),
            b"http/1.1" => Some(NpnProtocol::Http11),
            _ => None,
        }
    }
}

impl NpnNegotiator {
    pub fn new() -> Self {
        Self {
            supported_protocols: vec![
                NpnProtocol::Http2,
                NpnProtocol::Http11,
            ],
            selected_protocol: None,
        }
    }

    pub fn with_protocols(protocols: Vec<NpnProtocol>) -> Self {
        Self {
            supported_protocols: protocols,
            selected_protocol: None,
        }
    }

    pub fn supported_protocols_wire(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for protocol in &self.supported_protocols {
            let wire = protocol.wire_format();
            result.push(wire.len() as u8);
            result.extend_from_slice(wire);
        }

        result
    }

    pub fn negotiate(&mut self, server_protocols: &[u8]) -> Option<NpnProtocol> {
        let server_prefs = Self::parse_protocol_list(server_protocols)?;
        let selected = server_prefs.into_iter().find(|p| self.supported_protocols.contains(p));
        self.selected_protocol = selected;
        selected
    }

    fn parse_protocol_list(data: &[u8]) -> Option<Vec<NpnProtocol>> {
        let mut protocols = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            if pos >= data.len() {
                return None;
            }

            let len = data[pos] as usize;
            pos += 1;

            if pos + len > data.len() {
                return None;
            }

            if let Some(protocol) = NpnProtocol::from_wire(&data[pos..pos + len]) {
                protocols.push(protocol);
            }

            pos += len;
        }

        if protocols.is_empty() {
            None
        } else {
            Some(protocols)
        }
    }

    pub fn selected(&self) -> Option<NpnProtocol> {
        self.selected_protocol
    }

    pub fn reset(&mut self) {
        self.selected_protocol = None;
    }
}

impl fmt::Display for AlpnProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Default for AlpnNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for NpnNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpn_protocol_wire_format() {
        assert_eq!(AlpnProtocol::Http2.wire_format(), b"h2");
        assert_eq!(AlpnProtocol::Http11.wire_format(), b"http/1.1");
        assert_eq!(AlpnProtocol::Http3.wire_format(), b"h3");
    }

    #[test]
    fn test_alpn_protocol_from_wire() {
        assert_eq!(AlpnProtocol::from_wire(b"h2"), Some(AlpnProtocol::Http2));
        assert_eq!(AlpnProtocol::from_wire(b"http/1.1"), Some(AlpnProtocol::Http11));
        assert_eq!(AlpnProtocol::from_wire(b"invalid"), None);
    }

    #[test]
    fn test_alpn_protocol_priority() {
        assert!(AlpnProtocol::Http3.priority() > AlpnProtocol::Http2.priority());
        assert!(AlpnProtocol::Http2.priority() > AlpnProtocol::Http11.priority());
        assert!(AlpnProtocol::Http11.priority() > AlpnProtocol::Http10.priority());
    }

    #[test]
    fn test_alpn_negotiator_new() {
        let negotiator = AlpnNegotiator::new();
        assert!(negotiator.supported_protocols.contains(&AlpnProtocol::Http2));
        assert!(negotiator.supported_protocols.contains(&AlpnProtocol::Http11));
        assert!(!negotiator.is_negotiated());
    }

    #[test]
    fn test_alpn_negotiator_add_protocol() {
        let mut negotiator = AlpnNegotiator::new();
        negotiator.add_protocol(AlpnProtocol::Http3);
        assert!(negotiator.supported_protocols.contains(&AlpnProtocol::Http3));
    }

    #[test]
    fn test_alpn_supported_protocols_wire() {
        let negotiator = AlpnNegotiator::new();
        let wire = negotiator.supported_protocols_wire();
        assert!(!wire.is_empty());
        assert_eq!(wire[0], 2);
    }

    #[test]
    fn test_alpn_negotiate_server_preference() {
        let mut negotiator = AlpnNegotiator::new();
        negotiator.set_server_preference(true);

        let client_prefs = b"\x08http/1.1\x02h2";
        let selected = negotiator.negotiate(client_prefs);

        assert_eq!(selected, Ok(AlpnProtocol::Http2));
        assert!(negotiator.is_negotiated());
    }

    #[test]
    fn test_alpn_negotiate_client_preference() {
        let mut negotiator = AlpnNegotiator::new();
        negotiator.set_server_preference(false);

        let client_prefs = b"\x08http/1.1\x02h2";
        let selected = negotiator.negotiate(client_prefs);

        assert_eq!(selected, Ok(AlpnProtocol::Http11));
    }

    #[test]
    fn test_alpn_negotiate_no_match() {
        let mut negotiator = AlpnNegotiator::new();

        let client_prefs = b"\x02h3";
        let selected = negotiator.negotiate(client_prefs);

        assert!(selected.is_err());
    }

    #[test]
    fn test_alpn_parse_protocol_list() {
        let data = b"\x02h2\x08http/1.1";
        let protocols = AlpnNegotiator::new().supported_protocols_wire();
        assert!(!protocols.is_empty());
    }

    #[test]
    fn test_alpn_reset() {
        let mut negotiator = AlpnNegotiator::new();
        let client_prefs = b"\x02h2";
        negotiator.negotiate(client_prefs);
        assert!(negotiator.is_negotiated());

        negotiator.reset();
        assert!(!negotiator.is_negotiated());
    }

    #[test]
    fn test_npn_protocol_wire_format() {
        assert_eq!(NpnProtocol::Http2.wire_format(), b"h2");
        assert_eq!(NpnProtocol::Http11.wire_format(), b"http/1.1");
    }

    #[test]
    fn test_npn_negotiator_new() {
        let negotiator = NpnNegotiator::new();
        assert!(negotiator.supported_protocols.contains(&NpnProtocol::Http2));
    }

    #[test]
    fn test_npn_negotiate() {
        let mut negotiator = NpnNegotiator::new();
        let server_prefs = b"\x02h2\x08http/1.1";
        let selected = negotiator.negotiate(server_prefs);

        assert_eq!(selected, Some(NpnProtocol::Http2));
    }

    #[test]
    fn test_alpn_protocol_requirements() {
        assert!(AlpnProtocol::Http2.requires_tls());
        assert!(AlpnProtocol::Http3.requires_tls());
        assert!(!AlpnProtocol::Http11.requires_tls());
        assert!(!AlpnProtocol::Http10.requires_tls());
    }

    #[test]
    fn test_alpn_protocol_push_support() {
        assert!(AlpnProtocol::Http2.supports_push());
        assert!(AlpnProtocol::Http3.supports_push());
        assert!(!AlpnProtocol::Http11.supports_push());
        assert!(!AlpnProtocol::Http10.supports_push());
    }

    #[test]
    fn test_alpn_sorted_protocols() {
        let negotiator = AlpnNegotiator::new();
        let sorted = negotiator.supported_protocols_sorted();
        for i in 0..sorted.len() - 1 {
            assert!(sorted[i].priority() >= sorted[i + 1].priority());
        }
    }
}