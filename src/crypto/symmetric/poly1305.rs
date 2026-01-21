use crate::crypto::{Error, Result};

const CLAMP_MASK: [u8; 16] = [
    0xff, 0xff, 0xff, 0x0f, // r[0]
    0xfc, 0xff, 0xff, 0x0f, // r[1]
    0xfc, 0xff, 0xff, 0x0f, // r[2]
    0xfc, 0xff, 0xff, 0x0f, // r[3]
];

#[derive(Clone)]
pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    h: [u32; 5],
    buffer: [u8; 16],
    buffer_len: usize,
}

impl Poly1305 {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::InvalidKeySize);
        }

        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[..16]);
        for i in 0..16 {
            r_bytes[i] &= CLAMP_MASK[i];
        }

        let r = [
            u32::from_le_bytes([r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3]]) & 0x3ffffff,
            (u32::from_le_bytes([r_bytes[3], r_bytes[4], r_bytes[5], r_bytes[6]]) >> 2) & 0x3ffff03,
            (u32::from_le_bytes([r_bytes[6], r_bytes[7], r_bytes[8], r_bytes[9]]) >> 4) & 0x3ffc0ff,
            (u32::from_le_bytes([r_bytes[9], r_bytes[10], r_bytes[11], r_bytes[12]]) >> 6) & 0x3f03fff,
            (u32::from_le_bytes([r_bytes[12], r_bytes[13], r_bytes[14], r_bytes[15]]) >> 8) & 0x00fffff,
        ];

        let s = [
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        ];

        Ok(Poly1305 {
            r,
            s,
            h: [0; 5],
            buffer: [0u8; 16],
            buffer_len: 0,
        })
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        if self.buffer_len > 0 {
            let to_copy = (16 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;
            if self.buffer_len == 16 {
                let block = self.buffer;
                self.process_block(&block, false);
                self.buffer_len = 0;
            }
        }

        while offset + 16 <= data.len() {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[offset..offset + 16]);
            self.process_block(&block, false);
            offset += 16;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    pub fn finalize(mut self) -> Result<[u8; 16]> {
        if self.buffer_len > 0 {
            let mut final_block = [0u8; 16];
            final_block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
            self.process_block(&final_block, true);
        }

        self.reduce_h();
        let mut c = 0u64;
        for i in 0..4 {
            c += self.h[i] as u64 + self.s[i] as u64;
            self.h[i] = c as u32;
            c >>= 32;
        }

        c += self.h[4] as u64;
        self.h[4] = c as u32;

        let mut tag = [0u8; 16];
        for i in 0..4 {
            let bytes = self.h[i].to_le_bytes();
            tag[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }

        Ok(tag)
    }

    pub fn verify(self, expected: &[u8]) -> Result<()> {
        if expected.len() != 16 {
            return Err(Error::InvalidLength);
        }

        let computed = self.finalize()?;
        if !crate::crypto::constant_time_eq(&computed, expected) {
            return Err(Error::VerificationFailed);
        }

        Ok(())
    }

    fn process_block(&mut self, block: &[u8; 16], is_final: bool) {
        let hibit = if is_final { 0 } else { 1u32 << 24 };

        let mut c = self.h[0] as u64 + (u32::from_le_bytes([block[0], block[1], block[2], block[3]]) & 0x3ffffff) as u64;
        self.h[0] = c as u32;
        c >>= 32;

        c += self.h[1] as u64
            + ((u32::from_le_bytes([block[3], block[4], block[5], block[6]]) >> 2) & 0x3ffffff)
                as u64;
        self.h[1] = c as u32;
        c >>= 32;

        c += self.h[2] as u64
            + ((u32::from_le_bytes([block[6], block[7], block[8], block[9]]) >> 4) & 0x3ffffff)
                as u64;
        self.h[2] = c as u32;
        c >>= 32;

        c += self.h[3] as u64
            + ((u32::from_le_bytes([block[9], block[10], block[11], block[12]]) >> 6) & 0x3ffffff)
                as u64;
        self.h[3] = c as u32;
        c >>= 32;

        c += self.h[4] as u64
            + ((u32::from_le_bytes([block[12], block[13], block[14], block[15]]) >> 8) | hibit)
                as u64;
        self.h[4] = c as u32;

        let r0 = self.r[0] as u64;
        let r1 = self.r[1] as u64;
        let r2 = self.r[2] as u64;
        let r3 = self.r[3] as u64;
        let r4 = self.r[4] as u64;

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let h0 = self.h[0] as u64;
        let h1 = self.h[1] as u64;
        let h2 = self.h[2] as u64;
        let h3 = self.h[3] as u64;
        let h4 = self.h[4] as u64;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c = d0 >> 26;
        self.h[0] = (d0 & 0x3ffffff) as u32;
        d1 += c;

        c = d1 >> 26;
        self.h[1] = (d1 & 0x3ffffff) as u32;
        d2 += c;

        c = d2 >> 26;
        self.h[2] = (d2 & 0x3ffffff) as u32;
        d3 += c;

        c = d3 >> 26;
        self.h[3] = (d3 & 0x3ffffff) as u32;
        d4 += c;

        c = d4 >> 26;
        self.h[4] = (d4 & 0x3ffffff) as u32;
        self.h[0] += (c * 5) as u32;

        c = (self.h[0] >> 26) as u64;
        self.h[0] &= 0x3ffffff;
        self.h[1] += c as u32;
    }

    fn reduce_h(&mut self) {
        let mut c = (self.h[1] >> 26) as u64;
        self.h[1] &= 0x3ffffff;
        self.h[2] += c as u32;

        c = (self.h[2] >> 26) as u64;
        self.h[2] &= 0x3ffffff;
        self.h[3] += c as u32;

        c = (self.h[3] >> 26) as u64;
        self.h[3] &= 0x3ffffff;
        self.h[4] += c as u32;

        c = (self.h[4] >> 26) as u64;
        self.h[4] &= 0x3ffffff;
        self.h[0] += (c * 5) as u32;

        c = (self.h[0] >> 26) as u64;
        self.h[0] &= 0x3ffffff;
        self.h[1] += c as u32;

        let mut g = [0u32; 5];
        g[0] = self.h[0].wrapping_add(5);
        c = (g[0] >> 26) as u64;
        g[0] &= 0x3ffffff;
        for i in 1..5 {
            g[i] = self.h[i].wrapping_add(c as u32);
            c = (g[i] >> 26) as u64;
            g[i] &= 0x3ffffff;
        }

        let mask = ((c as i32) - 1) as u32;
        for i in 0..5 {
            g[i] ^= self.h[i];
            g[i] &= mask;
            self.h[i] ^= g[i];
        }
    }
}

pub fn poly1305(key: &[u8], data: &[u8]) -> Result<[u8; 16]> {
    let mut mac = Poly1305::new(key)?;
    mac.update(data);
    mac.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly1305_rfc8439() {
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];

        let msg = b"Cryptographic Forum Research Group";

        let expected = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
        ];

        let tag = poly1305(&key, msg).unwrap();
        assert_eq!(tag, expected);
    }

    #[test]
    fn test_poly1305_empty() {
        let key = [1u8; 32];
        let msg = b"";

        let tag = poly1305(&key, msg).unwrap();
        assert_eq!(tag.len(), 16);
    }

    #[test]
    fn test_poly1305_incremental() {
        let key = [1u8; 32];
        let msg = b"Hello, World!";

        let mut mac1 = Poly1305::new(&key).unwrap();
        mac1.update(msg);
        let tag1 = mac1.finalize().unwrap();

        let mut mac2 = Poly1305::new(&key).unwrap();
        mac2.update(&msg[..5]);
        mac2.update(&msg[5..]);
        let tag2 = mac2.finalize().unwrap();

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_poly1305_verify() {
        let key = [2u8; 32];
        let msg = b"Test message";

        let mut mac = Poly1305::new(&key).unwrap();
        mac.update(msg);
        let tag = mac.finalize().unwrap();

        let mut verify_mac = Poly1305::new(&key).unwrap();
        verify_mac.update(msg);
        assert!(verify_mac.verify(&tag).is_ok());
    }

    #[test]
    fn test_poly1305_verify_fail() {
        let key = [2u8; 32];
        let msg = b"Test message";

        let mut mac = Poly1305::new(&key).unwrap();
        mac.update(msg);
        let mut tag = mac.finalize().unwrap();

        tag[0] ^= 1;

        let mut verify_mac = Poly1305::new(&key).unwrap();
        verify_mac.update(msg);
        assert!(verify_mac.verify(&tag).is_err());
    }

    #[test]
    fn test_poly1305_multiple_blocks() {
        let key = [3u8; 32];
        let msg = [4u8; 100];

        let mut mac = Poly1305::new(&key).unwrap();
        mac.update(&msg);
        let tag = mac.finalize().unwrap();

        assert_eq!(tag.len(), 16);
    }
}