use std::io;
use std::net::{UdpSocket as StdUdpSocket, SocketAddr, ToSocketAddrs};
use std::time::Duration;

pub struct UdpSocket {
    socket: StdUdpSocket,
}

impl UdpSocket {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = StdUdpSocket::bind(addr)?;
        Ok(Self { socket })
    }

    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, addr)
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf)
    }

    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> io::Result<()> {
        self.socket.connect(addr)
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf)
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(timeout)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
        self.socket.set_broadcast(broadcast)
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
        })
    }

    pub fn send_recv_timeout(&self, send_buf: &[u8], recv_buf: &mut [u8], addr: SocketAddr, timeout: Duration) -> io::Result<usize> {
        self.set_read_timeout(Some(timeout))?;
        self.set_write_timeout(Some(timeout))?;
        self.send_to(send_buf, addr)?;
        let (size, _) = self.recv_from(recv_buf)?;

        Ok(size)
    }
}