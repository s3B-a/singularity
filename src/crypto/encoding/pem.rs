use crate::crypto::{Error, Result};

const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(input: &[u8]) -> String {
    let mut output = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i];
        let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };

        let idx0 = b0 >> 2;
        let idx1 = ((b0 & 0b0000_0011) << 4) | (b1 >> 4);
        let idx2 = ((b1 & 0b0000_1111) << 2) | (b2 >> 6);
        let idx3 = b2 & 0b0011_1111;

        output.push(BASE64_CHARS[idx0 as usize] as char);
        output.push(BASE64_CHARS[idx1 as usize] as char);

        if i + 1 < input.len() {
            output.push(BASE64_CHARS[idx2 as usize] as char);
        } else {
            output.push('=');
        }

        if i + 2 < input.len() {
            output.push(BASE64_CHARS[idx3 as usize] as char);
        } else {
            output.push('=');
        }

        i += 3;
    }
    output
}

pub fn decode(input: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buf = [0u8; 4];
    let mut buf_len = 0;

    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }

    for &b in input.as_bytes().iter().filter(|&&c| c != b'\n' && c != b'\r' && c != b' ') {
        if b == b'=' {
            buf[buf_len] = 0;
            buf_len += 1;
        } else if let Some(val) = decode_char(b) {
            buf[buf_len] = val;
            buf_len += 1;
        } else {
            return Err(Error::CryptoError("Invalid base64 character".to_string()));
        }

        if buf_len == 4 {
            output.push((buf[0] << 2) | (buf[1] >> 4));
            if input.as_bytes()[output.len() * 4 / 3 + 2 - 1] != b'=' {
                output.push((buf[1] << 4) | (buf[2] >> 2));
            }

            if input.as_bytes()[output.len() * 4 / 3 + 3 - 1] != b'=' {
                output.push((buf[2] << 6) | buf[3]);
            }

            buf_len = 0;
        }
    }
    
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(decode("").unwrap(), b"");
        assert_eq!(decode("Zg==").unwrap(), b"f");
        assert_eq!(decode("Zm8=").unwrap(), b"fo");
        assert_eq!(decode("Zm9v").unwrap(), b"foo");
        assert_eq!(decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn test_base64_decode_invalid() {
        assert!(decode("!!!").is_err());
        assert!(decode("Zm9v*YmFy").is_err());
    }
}