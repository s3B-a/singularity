mod connection;
mod error;
mod flow_control;
mod frame;
mod hpack;
mod priority;
mod settings;
mod stream;

pub use connection::Http2Connection;
pub use error::{ErrorCode, Http2Error, Result};
pub use flow_control::FlowControl;
pub use frame::{Frame, FrameFlags, FrameHeader, FrameType};
pub use hpack::HpackCodec;
pub use priority::{Priority, PriorityTree};
pub use settings::{Settings, SettingId};
pub use stream::{Http2Stream, StreamState};

pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// RFC 7540 standards
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65535;
pub const MAX_FRAME_SIZE: u32 = 16777215;
pub const MIN_FRAME_SIZE: u32 = 16384;