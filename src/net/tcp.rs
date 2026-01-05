use super::socket::Socket;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{ToSocketAddrs, SocketAddr};
use std::time::Duration;

pub struct TcpStream {
    socket: Socket,
    reader: BufReader<Socket>,
}

pub struct TcpListener {
    socket: Socket,
}

impl TcpListener {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = Socket::bind(addr)?;
        Ok(Self { socket })
    }

    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, addr) = self.socket.accept()?;
        Ok((TcpStream {
            socket: stream.try_clone()?,
            reader: BufReader::new(stream),
        }, addr))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
        })
    }

    pub fn incoming(&self) -> impl Iterator<Item = io::Result<TcpStream>> + '_ {
        std::iter::repeat_with(move || self.accept().map(|(stream, _)| stream))
    }
}

impl TcpStream {
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        Self::connect_timeout(addr, Duration::from_secs(30))
    }

    pub fn connect_timeout<A: ToSocketAddrs>(addr: A, timeout: Duration) -> io::Result<Self> {
        let socket = Socket::connect(addr, timeout)?;
        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(Duration::from_secs(30)))?;
        socket.set_write_timeout(Some(Duration::from_secs(30)))?;

        let reader_socket = socket.try_clone()?;
        let reader = BufReader::new(reader_socket);

        Ok(Self { socket, reader})
    }

    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.socket.write_all(data)
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.reader.get_mut().read_exact(buf)
    }

    pub fn read_until(&mut self, delimiter: u8, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.reader.read_until(delimiter, buf)
    }

    pub fn read_line(&mut self, buf: &mut String) -> io::Result<usize> {
        self.reader.read_line(buf)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.get_mut().read(buf)
    }

    pub fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.reader.get_mut().read_to_end(buf)
    }

    pub fn read_limited(&mut self, max_bytes: usize) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut chunk = vec![0u8; 8192];
        let mut total_read = 0;
        loop {
            let bytes_read = self.read(&mut chunk)?;
            if bytes_read == 0 {
                break;
            }

            total_read += bytes_read;
            if total_read > max_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Exceeded maximum allowed bytes",
                ));
            }

            buffer.extend_from_slice(&chunk[..bytes_read]);
        }

        Ok(buffer)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }

    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        self.socket.shutdown(how)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(timeout)
    }

    pub fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.peek(buf)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.socket.set_nodelay(nodelay)
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.get_mut().read(buf)
    }
}

impl Read for &TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.try_clone()?.read(buf)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

impl Write for &TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.try_clone()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.try_clone()?.flush()
    }
}