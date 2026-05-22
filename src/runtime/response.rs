use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub elapsed: Duration,
}

/// OS resolver result (`dns` probe without `port` / `payload`).
#[derive(Debug, Clone)]
pub struct DnsResolveResponse {
    pub host: String,
    pub answers: Vec<String>,
}

/// Raw bytes from TCP, UDP, or wire-format DNS (`host` + `port` + optional `payload`).
#[derive(Debug, Clone)]
pub struct SocketResponse {
    pub host: String,
    pub port: u16,
    pub data: String,
}

#[derive(Debug, Clone)]
pub enum ProbeResponse {
    Http(HttpResponse),
    DnsResolve(DnsResolveResponse),
    Socket(SocketResponse),
}

impl ProbeResponse {
    pub fn as_http(&self) -> Result<&HttpResponse, ()> {
        match self {
            Self::Http(inner) => Ok(inner),
            _ => Err(()),
        }
    }

    pub fn as_dns_resolve(&self) -> Result<&DnsResolveResponse, ()> {
        match self {
            Self::DnsResolve(inner) => Ok(inner),
            _ => Err(()),
        }
    }

    pub fn as_socket(&self) -> Result<&SocketResponse, ()> {
        match self {
            Self::Socket(inner) => Ok(inner),
            _ => Err(()),
        }
    }
}
