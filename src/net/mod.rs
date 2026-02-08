pub mod tcp;
pub mod udp;
pub mod socket;
pub mod http;
pub mod https;
pub mod dns;
pub mod cookie;
pub mod connection_pool;

#[cfg(feature = "https")]
pub mod https;

pub use tcp::TcpStream;
pub use udp::UdpSocket;
pub use http::HttpClient;
pub use dns::DnsResolver;
pub use cookie::CookieJar;

pub use crate::crypto as crypto;

use std::io;

pub type NetResult<T> = Result<T, NetErr>;

#[derive(Debug)]
pub enum NetErr {
    Io(io::Error),
    ConnectionFailed(String),
    Timeout,
    InvalidAddr,
    DnsResFailed,
    InvalidResponse,
    ConnectionClosed,
}

impl From<io::Error> for NetErr {
    fn from(err: io::Error) -> Self {
        NetErr::Io(err)
    }
}

impl std::fmt::Display for NetErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetErr::Io(e) => write!(f, "IO Error: {}", e),
            NetErr::ConnectionFailed(msg) => write!(f, "Connection Failed: {}", msg),
            NetErr::Timeout => write!(f, "Connection Timeout"),
            NetErr::InvalidAddr => write!(f, "Invalid Address"),
            NetErr::DnsResFailed => write!(f, "DNS Resolution Failed"),
            NetErr::InvalidResponse => write!(f, "Invalid Response"),
            NetErr::ConnectionClosed => write!(f, "Connection Closed"),
        }
    }
}

impl std::error::Error for NetErr {}