//! TCP port reachability cache (30s TTL), shared across executor runs in one process.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

use reqwest::Url;

use crate::runtime::context::VariableValue;
use crate::runtime::interpolate::interpolate;
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
        // Socket probes may use the documented `host "{{scan_host}}"` form,
        // which the executor resolves from `--target` at send-time. The
        // pre-run port check must resolve it identically, or it would probe
        // the literal placeholder, find it "closed", and skip the whole run.
        let scan_vars = scan_target_variables(base_url);
        let resolve =
            |host: &str| interpolate(host, &scan_vars).unwrap_or_else(|_| host.to_string());

        let mut out = Vec::new();
        for kind in spec.probes.values() {
            match kind {
                // Only connection-oriented TCP probes get a TCP-connect liveness
                // pre-check. UDP and wire-DNS probes are sent as connectionless
                // datagrams (`exchange_udp`), so a TCP connect to the same port
                // proves nothing about the UDP service — and would wrongly skip
                // the entire run for UDP-only hosts (NTP, SNMP, syslog, UDP-only
                // resolvers, …). Those probes rely on their own read timeout.
                ProbeKind::Tcp(socket) => {
                    if let Some(port) = socket.port {
                        out.push((normalize_host(&resolve(&socket.host)), port));
                    }
                }
                ProbeKind::Udp(_) | ProbeKind::Dns(_) | ProbeKind::Http(_) => {}
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

/// Build the `{{scan_host}}` / `{{scan_port}}` / `{{scan_url}}` variables from
/// the CLI `--target` (executor `base_url`). Mirrors the executor's
/// `inject_scan_target_variables` so the pre-run port check resolves socket
/// hosts the same way the send path does.
fn scan_target_variables(base_url: &str) -> HashMap<String, VariableValue> {
    let mut vars = HashMap::new();
    if let Some((host, port)) = scan_target_host_port(base_url) {
        vars.insert("scan_host".to_string(), VariableValue::String(host));
        vars.insert(
            "scan_port".to_string(),
            VariableValue::String(port.to_string()),
        );
    }
    if !base_url.is_empty() {
        vars.insert(
            "scan_url".to_string(),
            VariableValue::String(base_url.to_string()),
        );
    }
    vars
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

    fn tcp_spec(host: &str) -> ProgramSpec {
        use crate::runtime::spec::{CheckMetadata, SocketProbeSpec};
        let mut probes = std::collections::HashMap::new();
        probes.insert(
            "svc".to_string(),
            ProbeKind::Tcp(SocketProbeSpec {
                host: host.to_string(),
                port: Some(6379),
                ..SocketProbeSpec::default()
            }),
        );
        ProgramSpec {
            probes,
            metadata: CheckMetadata::default(),
        }
    }

    #[test]
    fn endpoints_interpolate_scan_host_for_socket_probes() {
        // The pre-run port check must resolve `{{scan_host}}` from --target,
        // just like the send path — otherwise socket probes are wrongly skipped.
        let eps = PortCache::endpoints_for_run(&tcp_spec("{{scan_host}}"), "http://127.0.0.1:6379");
        assert_eq!(eps, vec![("127.0.0.1".to_string(), 6379)]);
    }

    #[test]
    fn endpoints_keep_static_host_unchanged() {
        // A hardcoded host has no placeholder and must pass through verbatim,
        // with or without a --target (e.g. banner-grab probes).
        let eps = PortCache::endpoints_for_run(&tcp_spec("scanme.example.com"), "");
        assert_eq!(eps, vec![("scanme.example.com".to_string(), 6379)]);
    }

    fn single_probe_spec(kind: ProbeKind) -> ProgramSpec {
        use crate::runtime::spec::CheckMetadata;
        let mut probes = std::collections::HashMap::new();
        probes.insert("svc".to_string(), kind);
        ProgramSpec {
            probes,
            metadata: CheckMetadata::default(),
        }
    }

    #[test]
    fn udp_and_dns_probes_get_no_tcp_precheck() {
        use crate::runtime::spec::SocketProbeSpec;
        // UDP and wire-DNS are connectionless; a TCP-connect pre-check to their
        // port proves nothing and would wrongly skip the run on UDP-only hosts.
        let udp = single_probe_spec(ProbeKind::Udp(SocketProbeSpec {
            host: "{{scan_host}}".into(),
            port: Some(123),
            ..SocketProbeSpec::default()
        }));
        assert!(PortCache::endpoints_for_run(&udp, "http://127.0.0.1").is_empty());

        let dns = single_probe_spec(ProbeKind::Dns(SocketProbeSpec {
            host: "{{scan_host}}".into(),
            port: Some(53),
            ..SocketProbeSpec::default()
        }));
        assert!(PortCache::endpoints_for_run(&dns, "http://127.0.0.1").is_empty());
    }
}
