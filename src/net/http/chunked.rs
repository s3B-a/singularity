use std::io::{self, Read};

pub struct ChunkedDecoder<R> {
    reader: R,
}

impl<R: Read> ChunkedDecoder<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    pub fn decode(mut self) -> io::Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let chunk_size_line = self.read_line()?;
            let chunk_size = self.parse_chunk_size(&chunk_size_line)?;
            if chunk_size == 0 {
                // Read trailing headers if any and final CRLF
                self.read_trailing_headers()?;
                break;
            }

            let mut chunk_data = vec![0u8; chunk_size];
            self.reader.read_exact(&mut chunk_data)?;
            body.extend_from_slice(&chunk_data);
            self.read_line()?;
        }

        Ok(body)
    }

    fn read_line(&mut self) -> io::Result<String> {
        let mut line = String::new();
        let mut buffer = [0u8; 1];
        loop {
            self.reader.read_exact(&mut buffer)?;
            let ch = buffer[0] as char;
            if ch == '\n' {
                break;
            }

            if ch != 'r' {
                line.push(ch);
            }
        }

        Ok(line)
    }

    fn parse_chunk_size(&self, line: &str) -> io::Result<usize> {
        let size_part = line.split(';').next().unwrap_or(line).trim();
        usize::from_str_radix(size_part, 16)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid chunk size: {}", line)
                )
            })
    }

    fn read_trailing_headers(&mut self) -> io::Result<()> {
        loop {
            let line = self.read_line()?;
            if line.is_empty() {
                break;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_simple_chunk() {
        let data = b"5\r\nHello\r\n0\r\n\r\n";
        let decoder = ChunkedDecoder::new(&data[..]);
        let result = decoder.decode().unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_decode_multiple_chunks() {
        let data = b"5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
        let decoder = ChunkedDecoder::new(&data[..]);
        let result = decoder.decode().unwrap();
        assert_eq!(result, b"Hello World");
    }
}