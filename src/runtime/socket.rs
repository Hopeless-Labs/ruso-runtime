use std::time::Duration;

use crate::runtime::error::RuntimeError;
use crate::runtime::response::SocketResponse;
use crate::runtime::session::{
    ReadOpts, TcpSession, open_tcp_session, open_udp_session, read_opts_from_spec, tcp_exchange,
    udp_exchange,
};
use crate::runtime::spec::SocketProbeSpec;
use tokio::net::UdpSocket;

pub async fn exchange_tcp(
    host: &str,
    port: u16,
    spec: &SocketProbeSpec,
    verify_ssl: bool,
    connect_timeout: Duration,
    io_timeout: Duration,
) -> Result<SocketResponse, RuntimeError> {
    let mut session = open_tcp_session(host, port, spec.tls, verify_ssl, connect_timeout).await?;
    let read = read_opts_from_spec(spec);
    let data = tcp_exchange(&mut session, spec.payload.as_deref(), &read, io_timeout).await?;
    Ok(SocketResponse {
        host: host.to_string(),
        port,
        data,
    })
}

pub async fn exchange_udp(
    host: &str,
    port: u16,
    payload: Option<&[u8]>,
    spec: &SocketProbeSpec,
    connect_timeout: Duration,
    io_timeout: Duration,
) -> Result<SocketResponse, RuntimeError> {
    let socket = open_udp_session(host, port, connect_timeout).await?;
    let read = read_opts_from_spec(spec);
    let data = udp_exchange(&socket, payload, &read, io_timeout).await?;
    Ok(SocketResponse {
        host: host.to_string(),
        port,
        data,
    })
}

pub async fn tcp_session_exchange(
    session: &mut TcpSession,
    payload: Option<&[u8]>,
    read: &ReadOpts,
    io_timeout: Duration,
) -> Result<Vec<u8>, RuntimeError> {
    tcp_exchange(session, payload, read, io_timeout).await
}

pub async fn udp_session_exchange(
    socket: &UdpSocket,
    payload: Option<&[u8]>,
    read: &ReadOpts,
    io_timeout: Duration,
) -> Result<Vec<u8>, RuntimeError> {
    udp_exchange(socket, payload, read, io_timeout).await
}
