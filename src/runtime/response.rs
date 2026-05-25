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
///
/// `data` holds the response bytes exactly as received. For binary protocols
/// (SSH, MySQL, DNS wire, etc.) lossy UTF-8 conversion would replace non-text
/// bytes with `U+FFFD`, breaking byte-precise matching — so the runtime keeps
/// the raw bytes here and only decodes lossily when surfacing evidence to
/// humans via [`SocketResponse::data_lossy`].
#[derive(Debug, Clone)]
pub struct SocketResponse {
    pub host: String,
    pub port: u16,
    pub data: Vec<u8>,
}

impl SocketResponse {
    /// Lossy UTF-8 view of `data` for human-facing reporting only. Do not use
    /// for matching — bytes that are not valid UTF-8 become `U+FFFD`.
    pub fn data_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.data)
    }
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
