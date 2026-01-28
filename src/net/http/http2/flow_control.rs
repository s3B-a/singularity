use super::error::{ErrorCode, Http2Error, Result};

#[derive(Debug, Clone)]
pub struct FlowControl {
    window_size: i32,
    initial_window_size: u32,
}

impl FlowControl {
    pub fn new(initial_window_size: u32) -> Self {
        Self {
            window_size: initial_window_size as i32,
            initial_window_size,
        }
    }

    pub fn window_size(&self) -> i32 {
        self.window_size
    }

    pub fn can_send(&self, size: usize) -> bool {
        self.window_size >= size as i32
    }

    pub fn consume(&mut self, size: usize) -> Result<()> {
        if !self.can_send(size) {
            return Err(Http2Error::Protocol(
                ErrorCode::FlowControlError,
                "Flow control window exceeded".to_string()
            ));
        }

        self.window_size -= size as i32;
        Ok(())
    }

    pub fn increase(&mut self, increment: u32) -> Result<()> {
        if increment == 0 {
            return Err(Http2Error::Protocol(
                ErrorCode::ProtocolError,
                "Window update increment must be positive".to_string(),
            ));
        }

        let new_size = self.window_size as i64 + increment as i64;
        if new_size > i32::MAX as i64 {
            return Err(Http2Error::Protocol(
                ErrorCode::FlowControlError,
                "Flow control window overflow".to_string(),
            ));
        }

        self.window_size = new_size as i32;
        Ok(())
    }

    pub fn restore(&mut self, size: usize) {
        self.window_size += size as i32;
    }

    pub fn update_initial_window_size(&mut self, new_size: u32) -> Result<()> {
        let diff = new_size as i64 - self.initial_window_size as i64;
        let new_window = self.window_size as i64 + diff;
        if new_window > i32::MAX as i64 || new_window < i32::MIN as i64 {
            return Err(Http2Error::Protocol(
                ErrorCode::FlowControlError,
                "Flow control window overflow".to_string(),
            ));
        }

        self.window_size = new_window as i32;
        self.initial_window_size = new_size;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_control_consume() {
        let mut fc = FlowControl::new(65535);
        assert!(fc.can_send(1000));
        fc.consume(1000).unwrap();
        assert_eq!(fc.window_size(), 64535);
    }

    #[test]
    fn test_flow_control_increase() {
        let mut fc = FlowControl::new(65535);
        fc.consume(1000).unwrap();
        fc.increase(1000).unwrap();
        assert_eq!(fc.window_size(), 65535);
    }

    #[test]
    fn test_flow_control_overflow() {
        let mut fc = FlowControl::new(i32::MAX as u32);
        assert!(fc.increase(1).is_err());
    }
}