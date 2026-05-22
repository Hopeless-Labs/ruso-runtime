use crate::contract::{HttpMethod, ObjectBody};

#[derive(Debug, Clone, PartialEq)]
pub struct HttpRequestSpec {
    pub method: HttpMethod,
    pub path: String,
    pub timeout: Option<String>,
    pub follow_redirect: Option<bool>,
    pub verify_ssl: Option<bool>,
    pub proxy: Option<String>,
    pub user_agent: Option<String>,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub queries: Vec<(String, String)>,
    pub data_body: Option<ObjectBody>,
    pub json_body: Option<ObjectBody>,
    pub raw_body: Option<String>,
    pub body_bytes: Option<String>,
    pub multipart_body: Option<ObjectBody>,
}

impl Default for HttpRequestSpec {
    fn default() -> Self {
        Self {
            method: HttpMethod::Get,
            path: "/".into(),
            timeout: None,
            follow_redirect: None,
            verify_ssl: None,
            proxy: None,
            user_agent: None,
            headers: Vec::new(),
            cookies: Vec::new(),
            queries: Vec::new(),
            data_body: None,
            json_body: None,
            raw_body: None,
            body_bytes: None,
            multipart_body: None,
        }
    }
}

/// Generic socket options (shared by dns/tcp/udp probes).
#[derive(Debug, Clone, PartialEq)]
pub struct SocketProbeSpec {
    pub host: String,
    pub port: Option<u16>,
    pub payload: Option<Vec<u8>>,
    /// TLS handshake before application data (TCP only).
    pub tls: bool,
    /// Keep connection open across multiple `send` on the same probe name.
    pub session: bool,
    /// Maximum bytes to read per exchange (default 65536).
    pub read_max: u32,
    /// After first read, keep reading until idle for this many ms (0 = single read).
    pub read_idle_ms: u32,
}

impl Default for SocketProbeSpec {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: None,
            payload: None,
            tls: false,
            session: false,
            read_max: 65_536,
            read_idle_ms: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProbeKind {
    Http(HttpRequestSpec),
    Dns(SocketProbeSpec),
    Tcp(SocketProbeSpec),
    Udp(SocketProbeSpec),
}

#[derive(Debug, Clone, Default)]
pub struct CheckMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub impact: Option<String>,
    pub severity: Option<crate::contract::Severity>,
    pub author: Option<String>,
    pub report_title: Option<String>,
    pub cve: Vec<String>,
    pub cwe: Vec<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProgramSpec {
    pub probes: std::collections::HashMap<String, ProbeKind>,
    pub metadata: CheckMetadata,
}

impl SocketProbeSpec {
    pub fn is_dns_resolver_mode(&self) -> bool {
        self.port.is_none() && self.payload.is_none()
    }
}
