use std::fmt::Write;

pub fn encode(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 2);
    for ch in input.chars() {
        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(ch);
            }
            ':' | '/' | '?' | '#' | '[' | ']' | '@' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' => {
                result.push(ch);
            }
            _ => {
                percent_encode_char(ch, &mut result);
            }
        }
    }

    result
}

pub fn decode(input: &str) -> Result<String, String> {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '%' => {
                let hex1 = chars.next().ok_or_else(|| "Incomplete percent-encoding".to_string())?;
                let hex2 = chars.next().ok_or_else(|| "Incomplete percent-encoding".to_string())?;
                let hex_str = format!("{}{}", hex1, hex2);
                let byte = u8::from_str_radix(&hex_str, 16).map_err(|_| format!("Invalid percent encoding: %{}", hex_str))?;
                if byte < 128 {
                    result.push(byte as char);
                } else {
                    let mut bytes = vec![byte];
                    let additional_bytes = if byte & 0b1110_0000 == 0b1100_0000 {
                        1
                    } else if byte & 0b1111_0000 == 0b1110_0000 {
                        2
                    } else if byte & 0b1111_1000 == 0b1111_0000 {
                        3
                    } else {
                        return Err(format!("Invalid UTF-8 byte: {:02x}", byte));
                    };

                    for _ in 0..additional_bytes {
                        if chars.next() != Some('%') {
                            return Err("Invalid percent-encoding in multi-byte UTF-8 sequence".to_string());
                        }

                        let h1 = chars.next().ok_or_else(|| "Incomplete percent-encoding".to_string())?;
                        let h2 = chars.next().ok_or_else(|| "Incomplete percent-encoding".to_string())?;
                        let hex_str = format!("{}{}", h1, h2);
                        let b = u8::from_str_radix(&hex_str, 16).map_err(|_| format!("Invalid percent encoding: %{}", hex_str))?;
                        bytes.push(b);
                    }

                    let decoded_str = String::from_utf8(bytes).map_err(|_| "Invalid UTF-8 sequence".to_string())?;
                    result.push_str(&decoded_str);
                }
            }
            '+' => {
                result.push(' ');
            }
            _ => {
                result.push(ch);
            }
        }
    }

    Ok(result)
}

pub fn encode_component(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 2);
    for ch in input.chars() {
        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(ch);
            }
            _ => {
                percent_encode_char(ch, &mut result);
            }
        }
    }

    result
}

pub fn decode_component(input: &str) -> Result<String, String> {
    decode(input)
}

fn percent_encode_char(ch: char, result: &mut String) {
    let mut buffer = [0u8; 4];
    let bytes = ch.encode_utf8(&mut buffer).as_bytes();
    for &byte in bytes {
        let _ = write!(result, "%{:02X}", byte);
    }
}

pub fn encode_form(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 2);
    for ch in input.chars() {
        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(ch);
            }
            ' ' => {
                result.push('+');
            }
            _ => {
                percent_encode_char(ch, &mut result);
            }
        }
    }

    result
}

pub fn decode_form(input: &str) -> Result<String, String> {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '%' => {
                let hex1 = chars.next().ok_or_else(|| "Incomplete percent-encoding".to_string())?;
                let hex2 = chars.next().ok_or_else(|| "Incomplete percent-encoding".to_string())?;
                let hex_str = format!("{}{}", hex1, hex2);
                let byte = u8::from_str_radix(&hex_str, 16).map_err(|_| format!("Invalid percent encoding: %{}", hex_str))?;
                if byte < 128 {
                    result.push(byte as char);
                } else {
                    let mut bytes = vec![byte];
                    let additional_bytes = if byte & 0b1110_0000 == 0b1100_0000 {
                        1
                    } else if byte & 0b1111_0000 == 0b1110_0000 {
                        2
                    } else if byte & 0b1111_1000 == 0b1111_0000 {
                        3
                    } else {
                        return Err(format!("Invalid UTF-8 byte: {:02x}", byte));
                    };

                    for _ in 0..additional_bytes {
                        if chars.next() != Some('%') {
                            return Err("Invalid percent-encoding in multi-byte UTF-8 sequence".to_string());
                        }

                        let h1 = chars.next().ok_or_else(|| "Incomplete percent-encoding".to_string())?;
                        let h2 = chars.next().ok_or_else(|| "Incomplete percent-encoding".to_string())?;
                        let hex_str = format!("{}{}", h1, h2);
                        let b = u8::from_str_radix(&hex_str, 16).map_err(|_| format!("Invalid percent encoding: %{}", hex_str))?;
                        bytes.push(b);
                    }

                    let decoded_str = String::from_utf8(bytes).map_err(|_| "Invalid UTF-8 sequence".to_string())?;
                    result.push_str(&decoded_str);
                }
            }
            '+' => {
                result.push(' ');
            }
            _ => {
                result.push(ch);
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_unreserved() {
        assert_eq!(encode("Hello-World_123.txt~"), "Hello-World_123.txt~");
    }

    #[test]
    fn test_encode_reserved() {
        let input = "https://example.com/path?query=value#fragment";
        let encoded = encode(input);
        assert_eq!(encoded, input); // Reserved chars should not be encoded in full URL
    }

    #[test]
    fn test_encode_special_chars() {
        assert_eq!(encode("Hello World!"), "Hello%20World!");
        assert_eq!(encode("100%"), "100%25");
    }

    #[test]
    fn test_encode_unicode() {
        assert_eq!(encode("Hello 世界"), "Hello%20%E4%B8%96%E7%95%8C");
        assert_eq!(encode("Café"), "Caf%C3%A9");
    }

    #[test]
    fn test_decode_simple() {
        assert_eq!(decode("Hello%20World").unwrap(), "Hello World");
        assert_eq!(decode("100%25").unwrap(), "100%");
    }

    #[test]
    fn test_decode_plus() {
        assert_eq!(decode("Hello+World").unwrap(), "Hello World");
    }

    #[test]
    fn test_decode_unicode() {
        assert_eq!(decode("Hello%20%E4%B8%96%E7%95%8C").unwrap(), "Hello 世界");
        assert_eq!(decode("Caf%C3%A9").unwrap(), "Café");
    }

    #[test]
    fn test_decode_invalid() {
        assert!(decode("Hello%2").is_err());
        assert!(decode("Hello%ZZ").is_err());
    }

    #[test]
    fn test_encode_component() {
        assert_eq!(encode_component("hello world"), "hello%20world");
        assert_eq!(encode_component("a/b/c"), "a%2Fb%2Fc");
        assert_eq!(encode_component("key=value"), "key%3Dvalue");
    }

    #[test]
    fn test_decode_component() {
        assert_eq!(decode_component("hello%20world").unwrap(), "hello world");
        assert_eq!(decode_component("a%2Fb%2Fc").unwrap(), "a/b/c");
    }

    #[test]
    fn test_encode_form() {
        assert_eq!(encode_form("hello world"), "hello+world");
        assert_eq!(encode_form("key=value"), "key%3Dvalue");
        assert_eq!(encode_form("a&b"), "a%26b");
    }

    #[test]
    fn test_decode_form() {
        assert_eq!(decode_form("hello+world").unwrap(), "hello world");
        assert_eq!(decode_form("key%3Dvalue").unwrap(), "key=value");
    }

    #[test]
    fn test_round_trip() {
        let original = "Hello 世界! This is a test: 100% accurate.";
        let encoded = encode_component(original);
        let decoded = decode_component(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_round_trip_form() {
        let original = "Hello World! key=value & more";
        let encoded = encode_form(original);
        let decoded = decode_form(&encoded).unwrap();
        assert_eq!(decoded, original);
    }
}