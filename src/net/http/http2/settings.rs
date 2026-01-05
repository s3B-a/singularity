use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SettingId {
    HeaderTableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6,
}

impl SettingId {
    pub fn from_u16(id: u16) -> Option<Self> {
        match id {
            0x1 => Some(SettingId::HeaderTableSize),
            0x2 => Some(SettingId::EnablePush),
            0x3 => Some(SettingId::MaxConcurrentStreams),
            0x4 => Some(SettingId::InitialWindowSize),
            0x5 => Some(SettingId::MaxFrameSize),
            0x6 => Some(SettingId::MaxHeaderListSize),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    settings: HashMap<SettingId, u32>,
}

impl Settings {
    pub fn default() -> Self {
        let mut settings = HashMap::new();
        settings.insert(SettingId::HeaderTableSize, 4096);
        settings.insert(SettingId::EnablePush, 1);
        settings.insert(SettingId::MaxConcurrentStreams, u32::MAX);
        settings.insert(SettingId::InitialWindowSize, 65535);
        settings.insert(SettingId::MaxFrameSize, 16384);
        settings.insert(SettingId::MaxHeaderListSize, u32::MAX);

        Self { settings }
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, id: SettingId) -> u32 {
        *self.settings.get(&id).unwrap_or(&0)
    }

    pub fn set(&mut self, id: SettingId, value: u32) -> Result<(), String> {
        match id {
            SettingId::EnablePush => {
                if value > 1 {
                    return Err("ENABLE_PUSH must be 0 or 1".to_string());
                }
            }
            SettingId::InitialWindowSize => {
                if value > 2147483647 {
                    return Err("Initial window size too large".to_string());
                }
            }
            SettingId::MaxFrameSize => {
                if value < 16384 || value > 16777215 {
                    return Err("Max frame size out of range".to_string());
                }
            }
            _ => {}
        }

        self.settings.insert(id, value);
        Ok(())
    }

    pub fn header_table_size(&self) -> u32 {
        self.get(SettingId::HeaderTableSize)
    }

    pub fn enable_push(&self) -> bool {
        self.get(SettingId::EnablePush) == 1
    }

    pub fn max_concurrent_streams(&self) -> u32 {
        self.get(SettingId::MaxConcurrentStreams)
    }

    pub fn initial_window_size(&self) -> u32 {
        self.get(SettingId::InitialWindowSize)
    }

    pub fn max_frame_size(&self) -> u32 {
        self.get(SettingId::MaxFrameSize)
    }

    pub fn max_header_list_size(&self) -> u32 {
        self.get(SettingId::MaxHeaderListSize)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        for (id, &value) in &self.settings {
            data.extend_from_slice(&(id.clone() as u16).to_be_bytes());
            data.extend_from_slice(&value.to_be_bytes());
        }

        data
    }

    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() % 6 != 0 {
            return Err("Invalid settings frame size".to_string());
        }

        let mut settings = Settings::new();
        for chunk in data.chunks_exact(6) {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            if let Some(setting_id) = SettingId::from_u16(id) {
                settings.set(setting_id, value)?;
            }
        }

        Ok(settings)
    }
}