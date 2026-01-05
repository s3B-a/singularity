use super::{Headers, HttpResponse, HttpVersion, StatusCode};
use super::chunked::ChunkedDecoder;
use crate::net::tcp::TcpStream;
use std::io::{self};

pub struct HttpParser;

impl HttpParser {
    pub fn parse_response(stream: &mut TcpStream) -> io::Result<HttpResponse> {
        let status_line = Self::read_line(stream)?;
        let (version, status) = Self::parse_status_line(&status_line)?;
        let headers = Self::read_headers(stream)?;
        let body = Self::read_body(stream, &headers)?;
        let mut response = HttpResponse::new(status);

        response.set_version(version);
        response.set_headers(headers);
        response.set_body(body);

        Ok(response)
    }

    fn read_line(stream: &mut TcpStream) -> io::Result<String> {
        let mut line = String::new();
        stream.read_line(&mut line)?;
        if line.ends_with("\r\n") {
            line.truncate(line.len() - 2);
        } else if line.ends_with("\n") {
            line.truncate(line.len() - 1);
        }

        Ok(line)
    }

    fn parse_status_line(line: &str) -> io::Result<(HttpVersion, StatusCode)> {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid Status Line"
            ));
        }

        let version = HttpVersion::from_str(parts[0]).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid HTTP Version")
        })?;

        let status_code = parts[1].parse::<u16>().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid Status Code")
        })?;

        Ok((version, StatusCode::new(status_code)))
    }

    fn read_headers(stream: &mut TcpStream) -> io::Result<Headers> {
        let mut header_lines = Vec::new();
        loop {
            let line = Self::read_line(stream)?;
            if line.is_empty() {
                break;
            }

            header_lines.push(line);
        }

        Ok(Headers::parse(&header_lines))
    }

    fn read_body(stream: &mut TcpStream, headers: &Headers) -> io::Result<Vec<u8>> {
        if headers.is_chunked() {
            let decoder = ChunkedDecoder::new(stream);
            decoder.decode()
        } else if let Some(content_length) = headers.content_length() {
            let mut body = vec![0u8; content_length];
            stream.read_exact(&mut body)?;
            Ok(body)
        } else {
            let mut body = Vec::new();
            stream.read_to_end(&mut body)?;
            Ok(body)
        }
    }
}