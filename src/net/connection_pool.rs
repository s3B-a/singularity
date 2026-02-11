use super::tcp::TcpStream;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub total_hosts: usize,
    pub oldest_connection_age: Duration,
    pub total_requests_served: usize,
}

struct PooledConnection {
    stream: TcpStream,
    last_used: Instant,
    request_count: usize,
    created_at: Instant,
}

// Connection pool for reusing TCP connections (HTTP keep-alive)
pub struct ConnectionPool {
    connections: Arc<Mutex<HashMap<String, Vec<PooledConnection>>>>, // Keyed by host:port
    max_idle_per_host: usize, // Maximum idle connections to keep per host
    idle_timeout: Duration, // Duration after which idle connections are closed
    max_connection_age: Duration,
    max_requests_per_connection: usize,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_idle_per_host: 5,
            idle_timeout: Duration::from_secs(90),
            max_connection_age: Duration::from_secs(600),
            max_requests_per_connection: 100,
        }
    }

    pub fn with_config(max_idle_per_host: usize, idle_timeout: Duration) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_idle_per_host,
            idle_timeout,
            max_connection_age: Duration::from_secs(600),
            max_requests_per_connection: 100,
        }
    }

    pub fn with_limits(max_idle: usize, idle_timeout: Duration, max_age: Duration, max_requests: usize) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_idle_per_host: max_idle,
            idle_timeout,
            max_connection_age: max_age,
            max_requests_per_connection: max_requests,
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
            while let Some(mut conn) = connections.pop() {
                if conn.last_used.elapsed() < self.idle_timeout 
                    && conn.age() < self.max_connection_age
                    && conn.request_count < self.max_requests_per_connection {
                    
                    conn.mark_used();
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
            connections.push(PooledConnection::new(stream));
        }
    }

    pub fn clean_expired(&self) {
        let mut pool = self.connections.lock().unwrap();
        
        for connections in pool.values_mut() {
            connections.retain(|conn| {
                conn.last_used.elapsed() < self.idle_timeout
                    && conn.age() < self.max_connection_age
                    && conn.request_count < self.max_requests_per_connection
            });
        }

        pool.retain(|_, conns| !conns.is_empty());
    }

    pub fn clear(&self) {
        let mut pool = self.connections.lock().unwrap();
        pool.clear();
    }

    pub fn stats(&self) -> PoolStats {
        let pool = self.connections.lock().unwrap();
        
        let total_connections: usize = pool.values().map(|v| v.len()).sum();
        let total_hosts = pool.len();
        
        let mut oldest_age = Duration::from_secs(0);
        let mut total_requests = 0;
        
        for conns in pool.values() {
            for conn in conns {
                let age = conn.age();
                if age > oldest_age {
                    oldest_age = age;
                }
                total_requests += conn.request_count;
            }
        }

        PoolStats {
            total_connections,
            total_hosts,
            oldest_connection_age: oldest_age,
            total_requests_served: total_requests,
        }
    }

    pub fn connection_count(&self) -> usize {
        let pool = self.connections.lock().unwrap();
        pool.values().map(|v| v.len()).sum()
    }

    pub fn host_count(&self) -> usize {
        let pool = self.connections.lock().unwrap();
        pool.len()
    }
}

impl PooledConnection {
    fn new(stream: TcpStream) -> Self {
        let now = Instant::now();
        Self {
            stream,
            last_used: now,
            request_count: 0,
            created_at: now,
        }
    }

    fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    fn mark_used(&mut self) {
        self.last_used = Instant::now();
        self.request_count += 1;
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}