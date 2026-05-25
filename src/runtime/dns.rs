use std::time::Duration;

use crate::runtime::error::RuntimeError;
use crate::runtime::response::{DnsResolveResponse, SocketResponse};
use crate::runtime::socket::exchange_udp;
use crate::runtime::spec::SocketProbeSpec;

pub async fn resolve_host(host: &str) -> Result<DnsResolveResponse, RuntimeError> {
    let mut answers = Vec::new();
    let lookup = tokio::net::lookup_host((host, 0)).await?;
    for address in lookup {
        answers.push(address.ip().to_string());
    }
    Ok(DnsResolveResponse {
        host: host.to_string(),
        answers,
    })
}

pub async fn run_dns_probe(
    spec: &SocketProbeSpec,
    connect_timeout: Duration,
    io_timeout: Duration,
) -> Result<SocketResponse, RuntimeError> {
    let port = spec.port.unwrap_or(53);
    let host = spec.host.as_str();
    exchange_udp(
        host,
        port,
        spec.payload.as_deref(),
        spec,
        connect_timeout,
        io_timeout,
    )
    .await
}
