pub mod client;
pub mod headers;
pub mod method;
pub mod version;
pub mod request;
pub mod response;
pub mod http2;
pub mod status;
pub mod parser;
pub mod chunked;

pub use status::StatusCode;
pub use headers::Headers;
pub use method::HttpMethod;
pub use version::HttpVersion;
pub use client::{HttpClient, HttpClientBuilder};
pub use request::HttpRequest;
pub use response::HttpResponse;

#[cfg(test)]
mod tests;

pub mod advanced {
    pub use super::http2::{
        Http2Connection,
        Http2Error,
        ErrorCode,
        Settings,
        Priority,
    };
}