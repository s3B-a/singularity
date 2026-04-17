pub mod auth;
pub mod client;
pub mod headers;
pub mod method;
pub mod version;
pub mod request;
pub mod response;
pub mod http2;
pub mod http3;
pub mod http3_client;
pub mod status;
pub mod parser;
pub mod chunked;
pub mod trailer;
pub mod server;
pub mod negotiation;
pub mod compression;

pub use status::StatusCode;
pub use headers::Headers;
pub use method::HttpMethod;
pub use version::HttpVersion;
pub use client::{HttpClient, HttpClientBuilder};
pub use request::HttpRequest;
pub use trailer::TrailerHeaders;
pub use response::HttpResponse;
pub use server::{HttpServer, HttpServerCfg};
pub use negotiation::{ContentNegotiator, MediaType, LanguageTag, EncodingPreference};
pub use http3_client::Http3Client;
pub use crate::crypto as crypto;

pub use compression::{
    CompressionAlgorithm,
    CompressionConfig,
    CompressionLevel,
    compress as compress_body,
    decompress as decompress_body,
    detect_algorithm as detect_compression_algorithm,
    parse_accept_encoding,
};

pub const DEFAULT_USER_AGENT: &str = "Singularity/0.0.1";
pub const MAX_REDIRECTS: usize = 10;
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_ACCEPT_ENCODING: &str = "br, zstd, gzip, deflate, identity";

#[cfg(test)]
mod tests;

pub mod advanced {
    pub use super::http2::{
        Http2Connection,
        Http2Error,
        ErrorCode as Http2ErrorCode,
        Settings,
        Priority,
    };
    
    pub use super::http3::{
        QuicClient,
        QuicServer,
        QuicEndpoint,
        QuicConnectionManager,
        QuicStats,
        Http3Connection,
        Config as Http3Config,
        Error as Http3Error,
        ErrorCode as Http3ErrorCode,
    };
}