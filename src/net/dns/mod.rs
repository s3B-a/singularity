pub mod cache;
pub mod packet;
pub mod query;
pub mod record;
pub mod resolver;
pub mod response;

pub use resolver::DnsResolver;
pub use record::DnsRecord;