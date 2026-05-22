//! TCP port reachability cache (30s TTL), shared across executor runs in one process.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

use reqwest::Url;

use crate::runtime::spec::{ProbeKind, ProgramSpec};

const CACHE_TTL: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reachability {
    Open,
    Closed,
}

#[derive(Debug)]
struct Entry {
    state: Reachability,
    checked_at: Instant,
}

/// Result of probing one `host:port` (from cache or live TCP connect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortCheck {
    pub host: String,
    pub port: u16,
    pub open: bool,
}

#[derive(Debug)]
pub struct PortCache {
    entries: Mutex<HashMap<(String, u16), Entry>>,
}

impl PortCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(HashMap::new()),
        })
    }

    /// Process-wide cache so back-to-back checks in `ruso scan` reuse state.
    pub fn global() -> Arc<Self> {
        static CACHE: OnceLock<Arc<PortCache>> = OnceLock::new();
        CACHE.get_or_init(PortCache::new).clone()
    }

    /// Endpoints to probe before running: socket probes in the spec plus `--target` host:port for HTTP checks.
    pub fn endpoints_for_run(spec: &ProgramSpec, base_url: &str) -> Vec<(String, u16)> {
        let mut out = Vec::new();
        for kind in spec.probes.values() {
            match kind {
                ProbeKind::Tcp(socket) | ProbeKind::Udp(socket) => {
                    if let Some(port) = socket.port {
                        out.push((socket.host.clone(), port));
                    }
                }
                ProbeKind::Dns(socket) => {
                    if socket.is_dns_resolver_mode() {
                        continue;
                    }
                    let port = socket.port.unwrap_or(53);
                    out.push((socket.host.clone(), port));
                }
                ProbeKind::Http(_) => {}
            }
        }

        let has_http = spec.probes.values().any(|k| matches!(k, ProbeKind::Http(_)));
        if has_http {
            if let Some((host, port)) = host_port_from_base_url(base_url) {
                out.push((host, port));
            }
        }

        dedupe_endpoints(out)
    }

    /// Probe every endpoint for this run; returns checks and the first closed `(host, port)` if any.
    pub async fn check_for_run(
        &self,
        spec: &ProgramSpec,
        base_url: &str,
    ) -> (Vec<PortCheck>, Option<(String, u16)>) {
        let endpoints = Self::endpoints_for_run(spec, base_url);
        let mut checks = Vec::with_capacity(endpoints.len());
        let mut first_closed = None;

        for (host, port) in endpoints {
            let open = self.is_open(&host, port).await;
            checks.push(PortCheck {
                host: host.clone(),
                port,
                open,
            });
            if !open && first_closed.is_none() {
                first_closed = Some((host, port));
            }
        }

        (checks, first_closed)
    }

    pub async fn is_open(&self, host: &str, port: u16) -> bool {
        self.get_state(host, port).await == Reachability::Open
    }

    async fn get_state(&self, host: &str, port: u16) -> Reachability {
        let key = (host.to_string(), port);
        {
            let guard = self.entries.lock().await;
            if let Some(entry) = guard.get(&key) {
                if entry.checked_at.elapsed() < CACHE_TTL {
                    return entry.state;
                }
            }
        }

        let state = probe_tcp(host, port).await;
        let mut guard = self.entries.lock().await;
        guard.insert(
            key,
            Entry {
                state,
                checked_at: Instant::now(),
            },
        );
        state
    }
}

fn host_port_from_base_url(base_url: &str) -> Option<(String, u16)> {
    let url = Url::parse(base_url).ok()?;
    let host = url.host_str()?.to_string();
    let port = url
        .port()
        .unwrap_or_else(|| if url.scheme() == "https" { 443 } else { 80 });
    Some((host, port))
}

fn dedupe_endpoints(mut endpoints: Vec<(String, u16)>) -> Vec<(String, u16)> {
    endpoints.sort_unstable();
    endpoints.dedup();
    endpoints
}

async fn probe_tcp(host: &str, port: u16) -> Reachability {
    let address = format!("{host}:{port}");
    match timeout(CONNECT_TIMEOUT, TcpStream::connect(address.as_str())).await {
        Ok(Ok(_)) => Reachability::Open,
        _ => Reachability::Closed,
    }
}
