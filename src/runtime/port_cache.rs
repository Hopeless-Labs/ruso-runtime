//! TCP port reachability cache (30s TTL), shared across executor runs in one process.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

use reqwest::Url;

use crate::runtime::spec::{ProbeKind, ProgramSpec};

const CACHE_TTL: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);
/// Cap cache size to bound memory growth during long-running bulk scans.
/// At ~50 bytes per entry plus map overhead this is well under 1 MB.
const MAX_CACHE_ENTRIES: usize = 4096;

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
                        out.push((normalize_host(&socket.host), port));
                    }
                }
                ProbeKind::Dns(socket) => {
                    if socket.is_dns_resolver_mode() {
                        continue;
                    }
                    let port = socket.port.unwrap_or(53);
                    out.push((normalize_host(&socket.host), port));
                }
                ProbeKind::Http(_) => {}
            }
        }

        let has_http = spec
            .probes
            .values()
            .any(|k| matches!(k, ProbeKind::Http(_)));
        if has_http && let Some((host, port)) = scan_target_host_port(base_url) {
            out.push((host, port));
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
        let normalized = normalize_host(host);
        let key = (normalized, port);
        {
            let guard = self.entries.lock().await;
            if let Some(entry) = guard.get(&key)
                && entry.checked_at.elapsed() < CACHE_TTL
            {
                return entry.state;
            }
        }

        let state = probe_tcp(&key.0, port).await;
        let mut guard = self.entries.lock().await;
        // Evict the oldest entry if we'd otherwise exceed the cap. Linear
        // scan is fine at the 4K-entry scale — bulk scans grow this slowly.
        if guard.len() >= MAX_CACHE_ENTRIES
            && !guard.contains_key(&key)
            && let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, e)| e.checked_at)
                .map(|(k, _)| k.clone())
        {
            guard.remove(&oldest_key);
        }
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

/// Host and port from CLI `--target` / executor `base_url` (for `{{scan_host}}` / `{{scan_port}}`).
pub fn scan_target_host_port(base_url: &str) -> Option<(String, u16)> {
    let url = Url::parse(base_url).ok()?;
    let host = url.host_str()?;
    let port = url
        .port()
        .unwrap_or_else(|| if url.scheme() == "https" { 443 } else { 80 });
    Some((normalize_host(host), port))
}

/// Canonicalize a host string so equivalent IPv6 representations
/// (`::1`, `0:0:0:0:0:0:0:1`) and arbitrary case in hostnames share one
/// cache entry. Falls back to the original string on unknown formats.
fn normalize_host(host: &str) -> String {
    // Strip any surrounding brackets so `[::1]` and `::1` normalize the same.
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return ip.to_string();
    }
    host.to_ascii_lowercase()
}

fn dedupe_endpoints(mut endpoints: Vec<(String, u16)>) -> Vec<(String, u16)> {
    endpoints.sort_unstable();
    endpoints.dedup();
    endpoints
}

/// Format a `host:port` socket address, bracketing literal IPv6 addresses
/// so they parse correctly via `tokio::net::TcpStream::connect`.
pub fn format_socket_addr(host: &str, port: u16) -> String {
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if trimmed.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{trimmed}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn probe_tcp(host: &str, port: u16) -> Reachability {
    let address = format_socket_addr(host, port);
    match timeout(CONNECT_TIMEOUT, TcpStream::connect(address.as_str())).await {
        Ok(Ok(_)) => Reachability::Open,
        _ => Reachability::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_ipv6_collapses_long_form() {
        assert_eq!(normalize_host("::1"), normalize_host("0:0:0:0:0:0:0:1"));
        assert_eq!(normalize_host("[::1]"), normalize_host("::1"));
    }

    #[test]
    fn normalize_hostname_lowercases() {
        assert_eq!(normalize_host("Example.COM"), "example.com");
    }

    #[test]
    fn format_socket_addr_brackets_ipv6() {
        assert_eq!(format_socket_addr("::1", 443), "[::1]:443");
    }

    #[test]
    fn format_socket_addr_passes_through_ipv4() {
        assert_eq!(format_socket_addr("127.0.0.1", 80), "127.0.0.1:80");
    }

    #[test]
    fn format_socket_addr_passes_through_hostname() {
        assert_eq!(format_socket_addr("example.com", 80), "example.com:80");
    }

    #[test]
    fn scan_target_handles_ipv6_url() {
        let (host, port) = scan_target_host_port("http://[::1]:8080/api").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 8080);
    }
}
