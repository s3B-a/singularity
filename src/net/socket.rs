use std::io::{self, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs, TcpStream as StdTcpStream};
use std::time::Duration;

pub struct Socket {
    inner: StdTcpStream,
}

impl Socket {
    pub fn from_stream(stream: StdTcpStream) -> Self {
        Self { inner: stream }
    }

    pub fn connect<A: ToSocketAddrs>(addr: A, timeout: Duration) -> io::Result<Self> {
        let addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();
        if addrs.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "No valid addresses found"));
        }

        let mut last_err = None;
        for addr in addrs {
            match StdTcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => return Ok(Self::from_stream(stream)),
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "Connection failed")))
    }

    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let listener = std::net::TcpListener::bind(addr)?;
        let (stream, _) = listener.accept()?;
        Ok(Self {
            inner: stream,
        })
    }

    pub fn accept(&self) -> io::Result<(Self, SocketAddr)> {
        let listener = std::net::TcpListener::bind(self.inner.local_addr()?)?;
        let (stream, addr) = listener.accept()?;
        Ok((Self { inner: stream }, addr))
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            inner: self.inner.try_clone()?,
        })
    }

    pub fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.peek(buf)
    }
}

impl Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}