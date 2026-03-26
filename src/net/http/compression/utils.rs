const CRC32_TABLE: [u32; 256] = generate_crc32_table();

const fn generate_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = 0xedb88320 ^ (crc >> 1);
            } else {
                crc >>= 1;
            }

            j += 1;
        }

        table[i] = crc;
        i += 1;
    }
    
    table
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffffffff;
    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xff) as usize;
        crc = CRC32_TABLE[index] ^ (crc >> 8);
    }

    crc ^ 0xffffffff
}

pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let mut crc = crc ^ 0xffffffff;
    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xff) as usize;
        crc = CRC32_TABLE[index] ^ (crc >> 8);
    }

    crc ^ 0xffffffff
}

pub fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    (b << 16) | a
}

pub fn adler32_update(adler: u32, data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a = (adler & 0xffff) as u32;
    let mut b = (adler >> 16) as u32;
    for &byte in data {
        a = (a + byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    (b << 16) | a
}

pub fn bytes_needed(value: u64) -> usize {
    if value == 0 {
        return 1;
    }

    let mut bytes = 0;
    let mut v = value;
    while v > 0 {
        bytes += 1;
        v >>= 8;
    }

    bytes
}

pub fn reverse_bits(byte: u8) -> u8 {
    let mut result = 0u8;
    let mut b = byte;
    for _ in 0..8 {
        result = (result << 1) | (b & 1);
        b >>= 1;
    }

    result
}

pub fn reverse_bits_u16(value: u16, num_bits: u8) -> u16 {
    let mut result = 0u16;
    let mut v = value;
    for _ in 0..num_bits {
        result = (result << 1) | (v & 1);
        v >>= 1;
    }

    result
}

pub struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    pub fn read_bits(&mut self, n: u8) -> Option<u32> {
        if n > 32 {
            return None;
        }

        let mut result = 0u32;
        let mut bits_read = 0u8;
        while bits_read < n {
            if self.byte_pos >= self.data.len() {
                return None;
            }

            let bits_available = 8 - self.bit_pos;
            let bits_to_read = (n - bits_read).min(bits_available);
            
            let byte = self.data[self.byte_pos];
            let shift = bits_available - bits_to_read;
            let mask = if bits_to_read == 8 { 0xffu32 } else { (1u32 << bits_to_read) - 1 };
            let bits = ((byte as u32 >> shift) & mask);
            
            result = (result << bits_to_read) | bits;
            bits_read += bits_to_read;
            self.bit_pos += bits_to_read;

            if self.bit_pos >= 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }
        }

        Some(result)
    }

    pub fn align_to_byte(&mut self) {
        if self.bit_pos != 0 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }

    pub fn position(&self) -> usize {
        self.byte_pos
    }

    pub fn has_more(&self) -> bool {
        self.byte_pos < self.data.len()
    }

    pub fn peek_bits(&self, n: u8) -> Option<u32> {
        let mut temp = self.clone();
        temp.read_bits(n)
    }
}

pub struct BitWriter {
    data: Vec<u8>,
    current_byte: u8,
    bit_pos: u8,
}

impl BitWriter {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            current_byte: 0,
            bit_pos: 0,
        }
    }

    pub fn write_bits(&mut self, value: u32, n: u8) {
        if n == 0 || n > 32 {
            return;
        }

        for i in (0..n).rev() {
            let bit = ((value >> i) & 1) as u8;
            self.current_byte = (self.current_byte << 1) | bit;
            self.bit_pos += 1;
            
            if self.bit_pos >= 8 {
                self.data.push(self.current_byte);
                self.current_byte = 0;
                self.bit_pos = 0;
            }
        }
    }

    pub fn write_bits_reverse(&mut self, value: u32, n: u8) {
        for i in 0..n {
            let bit = ((value >> i) & 1) as u8;
            self.current_byte = (self.current_byte << 1) | bit;
            self.bit_pos += 1;
            if self.bit_pos >= 8 {
                self.data.push(self.current_byte);
                self.current_byte = 0;
                self.bit_pos = 0;
            }
        }
    }

    pub fn align_to_byte(&mut self) {
        if self.bit_pos != 0 {
            self.current_byte <<= 8 - self.bit_pos;
            self.data.push(self.current_byte);
            self.current_byte = 0;
            self.bit_pos = 0;
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        if self.bit_pos != 0 {
            self.current_byte <<= 8 - self.bit_pos;
            self.data.push(self.current_byte);
        }
        
        self.data
    }

    pub fn len(&self) -> usize {
        self.data.len() + if self.bit_pos > 0 { 1 } else { 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty() && self.bit_pos == 0
    }
}

pub struct SlidingWindow {
    buffer: Vec<u8>,
    size: usize,
    pub pos: usize,
}

impl SlidingWindow {
    pub fn new(size: usize) -> Self {
        Self {
            buffer: vec![0; size],
            size,
            pos: 0,
        }
    }

    pub fn push(&mut self, byte: u8) {
        self.buffer[self.pos] = byte;
        self.pos = (self.pos + 1) % self.size;
    }

    pub fn push_slice(&mut self, data: &[u8]) {
        for &byte in data {
            self.push(byte);
        }
    }

    pub fn get(&self, offset: usize) -> Option<u8> {
        if offset > self.size || offset == 0 {
            return None;
        }

        let idx = (self.pos + self.size - offset) % self.size;
        Some(self.buffer[idx])
    }

    pub fn find_match(&self, data: &[u8], max_length: usize) -> Option<(usize, usize)> {
        if data.is_empty() || max_length == 0 {
            return None;
        }

        let mut best_match: Option<(usize, usize)> = None;
        let max_length = max_length.min(data.len()).min(258);
        for offset in 1..=self.size.min(self.pos) {
            let idx = (self.pos + self.size - offset) % self.size;
            let mut match_len = 0;
            while match_len < max_length && match_len < data.len() {
                let window_byte = self.buffer[(idx + match_len) % self.size];
                let data_byte = data[match_len];
                
                if window_byte != data_byte {
                    break;
                }
                match_len += 1;
            }
            
            if match_len > 0 {
                if let Some((_, best_len)) = best_match {
                    if match_len > best_len {
                        best_match = Some((offset, match_len));
                    }
                } else {
                    best_match = Some((offset, match_len));
                }
            }
        }

        best_match
    }

    pub fn clear(&mut self) {
        self.buffer.fill(0);
        self.pos = 0;
    }
}

impl<'a> Clone for BitReader<'a> {
    fn clone(&self) -> Self {
        Self {
            data: self.data,
            byte_pos: self.byte_pos,
            bit_pos: self.bit_pos,
        }
    }
}

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_empty() {
        assert_eq!(crc32(&[]), 0);
    }

    #[test]
    fn test_crc32_known_values() {
        assert_eq!(crc32(b"123456789"), 0xcbf43926);
    }

    #[test]
    fn test_crc32_update() {
        let data = b"Hello, World!";
        let crc1 = crc32(data);
        
        let crc_part1 = crc32_update(0, &data[..5]);
        let crc_part2 = crc32_update(crc_part1, &data[5..]);
        
        assert_eq!(crc1, crc_part2);
    }

    #[test]
    fn test_adler32_empty() {
        assert_eq!(adler32(&[]), 1);
    }

    #[test]
    fn test_adler32_known_values() {
        let result = adler32(b"Wikipedia");
        assert!(result > 0);
    }

    #[test]
    fn test_adler32_update() {
        let data = b"Hello, World!";
        let adler1 = adler32(data);
        
        let adler_part1 = adler32_update(1, &data[..5]);
        let adler_part2 = adler32_update(adler_part1, &data[5..]);
        
        assert_eq!(adler1, adler_part2);
    }

    #[test]
    fn test_bit_reader_basic() {
        let data = vec![0b10110010];
        let mut reader = BitReader::new(&data);
        
        assert_eq!(reader.read_bits(2), Some(0b10));
        assert_eq!(reader.read_bits(3), Some(0b110));
        assert_eq!(reader.read_bits(3), Some(0b010));
    }

    #[test]
    fn test_bit_reader_align() {
        let data = vec![0b10110010, 0b11001101];
        let mut reader = BitReader::new(&data);
        
        reader.read_bits(3).unwrap();
        reader.align_to_byte();
        assert_eq!(reader.position(), 1);
    }

    #[test]
    fn test_bit_writer_basic() {
        let mut writer = BitWriter::new();
        
        writer.write_bits(0b10, 2);
        writer.write_bits(0b110, 3);
        writer.write_bits(0b010, 3);
        
        let result = writer.finish();
        assert_eq!(result[0], 0b10110010);
    }

    #[test]
    fn test_bit_writer_align() {
        let mut writer = BitWriter::new();
        
        writer.write_bits(0b101, 3);
        writer.align_to_byte();
        
        let result = writer.finish();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 0b10100000);
    }

    #[test]
    fn test_bit_roundtrip() {
        let mut writer = BitWriter::new();
        writer.write_bits(0b1010, 4);
        writer.write_bits(0b110011, 6);
        writer.write_bits(0b11, 2);
        
        let data = writer.finish();
        let mut reader = BitReader::new(&data);
        
        assert_eq!(reader.read_bits(4), Some(0b1010));
        assert_eq!(reader.read_bits(6), Some(0b110011));
        assert_eq!(reader.read_bits(2), Some(0b11));
    }

    #[test]
    fn test_sliding_window_basic() {
        let mut window = SlidingWindow::new(8);
        
        window.push(1);
        window.push(2);
        window.push(3);
        
        assert_eq!(window.get(0), None);
        assert_eq!(window.get(1), Some(3));
        assert_eq!(window.get(2), Some(2));
        assert_eq!(window.get(3), Some(1));
    }

    #[test]
    fn test_sliding_window_wrap() {
        let mut window = SlidingWindow::new(4);
        
        for i in 0..10 {
            window.push(i);
        }
        
        assert_eq!(window.get(1), Some(9));
        assert_eq!(window.get(2), Some(8));
        assert_eq!(window.get(3), Some(7));
        assert_eq!(window.get(4), Some(6));
    }

    #[test]
    fn test_sliding_window_find_match() {
        let mut window = SlidingWindow::new(32);
        let pattern = b"HELLO";
        
        window.push_slice(pattern);
        window.push_slice(b" WORLD ");
        
        let search = b"HEL";
        let result = window.find_match(search, 10);
        
        assert!(result.is_some(), "Expected to find a match for 'HEL'");
        if let Some((offset, length)) = result {
            assert!(length >= 3, "Expected match length >= 3, got {}", length);
            assert!(offset > 0, "Expected positive offset");
        }
    }

    #[test]
    fn test_reverse_bits() {
        assert_eq!(reverse_bits(0b10110010), 0b01001101);
        assert_eq!(reverse_bits(0b00000001), 0b10000000);
        assert_eq!(reverse_bits(0b11111111), 0b11111111);
    }

    #[test]
    fn test_reverse_bits_u16() {
        assert_eq!(reverse_bits_u16(0b101, 3), 0b101);
        assert_eq!(reverse_bits_u16(0b110, 3), 0b011);
        assert_eq!(reverse_bits_u16(0b1010, 4), 0b0101);
    }

    #[test]
    fn test_bytes_needed() {
        assert_eq!(bytes_needed(0), 1);
        assert_eq!(bytes_needed(255), 1);
        assert_eq!(bytes_needed(256), 2);
        assert_eq!(bytes_needed(65535), 2);
        assert_eq!(bytes_needed(65536), 3);
    }

    #[test]
    fn test_bit_reader_peek() {
        let data = vec![0b10110010];
        let reader = BitReader::new(&data);
        
        assert_eq!(reader.peek_bits(2), Some(0b10));
        assert_eq!(reader.peek_bits(2), Some(0b10));
    }
}