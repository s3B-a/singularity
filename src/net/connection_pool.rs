use super::tcp::TcpStream;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct PooledConnection {
    stream: TcpStream,
    last_used: Instant,
}

// Connection pool for reusing TCP connections (HTTP keep-alive)
pub struct ConnectionPool {
    connections: Arc<Mutex<HashMap<String, Vec<PooledConnection>>>>, // Keyed by host:port
    max_idle_per_host: usize, // Maximum idle connections to keep per host
    idle_timeout: Duration, // Duration after which idle connections are closed
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_idle_per_host: 5,
            idle_timeout: Duration::from_secs(90),
        }
    }

    pub fn with_config(max_idle_per_host: usize, idle_timeout: Duration) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_idle_per_host,
            idle_timeout,
        }
    }

    pub fn get_or_connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        let key = format!("{}:{}", host, port);
        if let Some(stream) = self.try_get(&key) {
            return Ok(stream);
        }

        let addr = format!("{}:{}", host, port);
        TcpStream::connect(addr)
    }

    fn try_get(&self, key: &str) -> Option<TcpStream> {
        let mut pool = self.connections.lock().unwrap();
        if let Some(connections) = pool.get_mut(key) {
            while let Some(conn) = connections.pop() {
                if conn.last_used.elapsed() < self.idle_timeout {
                    return Some(conn.stream);
                }
            }
        }

        None
    }

    pub fn return_connection(&self, host: &str, port: u16, stream: TcpStream) {
        let key = format!("{}:{}", host, port);
        let mut pool = self.connections.lock().unwrap();
        let connections = pool.entry(key).or_insert_with(Vec::new);
        if connections.len() < self.max_idle_per_host {
            connections.push(PooledConnection {
                stream,
                last_used: Instant::now(),
            });
        }
    }

    pub fn clean_expired(&self) {
        let mut pool = self.connections.lock().unwrap();
        for connections in pool.values_mut() {
            connections.retain(|conn| conn.last_used.elapsed() < self.idle_timeout);   
        }

        pool.retain(|_, conns| !conns.is_empty());
    }

    pub fn clear(&self) {
        let mut pool = self.connections.lock().unwrap();
        pool.clear();
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}