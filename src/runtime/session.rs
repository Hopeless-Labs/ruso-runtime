use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::runtime::error::RuntimeError;
use crate::runtime::spec::SocketProbeSpec;

pub struct ReadOpts {
    pub max_bytes: usize,
    pub idle_ms: u32,
}

/// Connected stream for stateful TCP (plain or TLS).
#[derive(Debug)]
pub enum TcpSession {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

#[derive(Debug)]
pub enum ProbeSession {
    Tcp(TcpSession),
    Udp(UdpSocket),
}

pub async fn open_tcp_session(
    host: &str,
    port: u16,
    tls: bool,
    verify_ssl: bool,
    connect_timeout: Duration,
) -> Result<TcpSession, RuntimeError> {
    let address = format!("{host}:{port}");
    let stream = timeout(connect_timeout, TcpStream::connect(&address))
        .await
        .map_err(|_| RuntimeError::Other(format!("tcp connect timeout: {address}")))??;

    if !tls {
        return Ok(TcpSession::Plain(stream));
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());

    let config = if verify_ssl {
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    };

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| RuntimeError::Other(format!("invalid tls server name: {host}")))?;
    let tls_stream = timeout(connect_timeout, connector.connect(server_name, stream))
        .await
        .map_err(|_| RuntimeError::Other(format!("tls handshake timeout: {address}")))??;

    Ok(TcpSession::Tls(Box::new(tls_stream)))
}

pub async fn open_udp_session(
    host: &str,
    port: u16,
    connect_timeout: Duration,
) -> Result<UdpSocket, RuntimeError> {
    let address = format!("{host}:{port}");
    let socket = timeout(connect_timeout, UdpSocket::bind("0.0.0.0:0"))
        .await
        .map_err(|_| RuntimeError::Other("udp bind timeout".into()))??;
    timeout(connect_timeout, socket.connect(&address))
        .await
        .map_err(|_| RuntimeError::Other(format!("udp connect timeout: {address}")))??;
    Ok(socket)
}

pub async fn tcp_exchange(
    session: &mut TcpSession,
    payload: Option<&[u8]>,
    read: &ReadOpts,
    io_timeout: Duration,
) -> Result<Vec<u8>, RuntimeError> {
    if let Some(payload) = payload {
        write_tcp(session, payload, io_timeout).await?;
    }
    read_tcp(session, read, io_timeout).await
}

pub async fn udp_exchange(
    socket: &UdpSocket,
    payload: Option<&[u8]>,
    read: &ReadOpts,
    io_timeout: Duration,
) -> Result<Vec<u8>, RuntimeError> {
    if let Some(payload) = payload {
        timeout(io_timeout, socket.send(payload))
            .await
            .map_err(|_| RuntimeError::Other("udp send timeout".into()))??;
    }
    read_udp(socket, read, io_timeout).await
}

async fn write_tcp(
    session: &mut TcpSession,
    payload: &[u8],
    io_timeout: Duration,
) -> Result<(), RuntimeError> {
    match session {
        TcpSession::Plain(stream) => {
            timeout(io_timeout, stream.write_all(payload))
                .await
                .map_err(|_| RuntimeError::Other("tcp write timeout".into()))??;
        }
        TcpSession::Tls(stream) => {
            timeout(io_timeout, stream.write_all(payload))
                .await
                .map_err(|_| RuntimeError::Other("tcp write timeout".into()))??;
        }
    }
    Ok(())
}

async fn read_tcp(
    session: &mut TcpSession,
    read: &ReadOpts,
    io_timeout: Duration,
) -> Result<Vec<u8>, RuntimeError> {
    match session {
        TcpSession::Plain(stream) => read_stream_plain(stream, read, io_timeout).await,
        TcpSession::Tls(stream) => read_stream_tls(stream, read, io_timeout).await,
    }
}

async fn read_udp(
    socket: &UdpSocket,
    read: &ReadOpts,
    io_timeout: Duration,
) -> Result<Vec<u8>, RuntimeError> {
    let mut out = Vec::new();
    let mut buffer = vec![0u8; 4096.min(read.max_bytes.max(1))];
    let idle = Duration::from_millis(read.idle_ms as u64);

    loop {
        let read_fut = socket.recv(&mut buffer);
        let chunk = if read.idle_ms > 0 {
            match timeout(idle, read_fut).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(RuntimeError::Other(e.to_string())),
                Err(_) => break,
            }
        } else {
            timeout(io_timeout, read_fut)
                .await
                .map_err(|_| RuntimeError::Other("udp recv timeout".into()))??
        };

        if chunk == 0 {
            break;
        }
        let take = chunk.min(read.max_bytes.saturating_sub(out.len()));
        out.extend_from_slice(&buffer[..take]);
        if out.len() >= read.max_bytes {
            break;
        }
        if read.idle_ms == 0 {
            break;
        }
    }
    Ok(out)
}

async fn read_stream_plain(
    stream: &mut TcpStream,
    read: &ReadOpts,
    io_timeout: Duration,
) -> Result<Vec<u8>, RuntimeError> {
    read_stream_impl(stream, read, io_timeout).await
}

async fn read_stream_tls(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    read: &ReadOpts,
    io_timeout: Duration,
) -> Result<Vec<u8>, RuntimeError> {
    read_stream_impl(stream, read, io_timeout).await
}

async fn read_stream_impl<S: AsyncRead + Unpin>(
    stream: &mut S,
    read: &ReadOpts,
    io_timeout: Duration,
) -> Result<Vec<u8>, RuntimeError> {
    let mut out = Vec::new();
    let mut buffer = vec![0u8; 4096.min(read.max_bytes.max(1))];
    let idle = Duration::from_millis(read.idle_ms as u64);

    loop {
        let read_fut = stream.read(&mut buffer);
        let chunk = if read.idle_ms > 0 {
            match timeout(idle, read_fut).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(RuntimeError::Other(e.to_string())),
                Err(_) => break,
            }
        } else {
            timeout(io_timeout, read_fut)
                .await
                .map_err(|_| RuntimeError::Other("tcp read timeout".into()))??
        };

        if chunk == 0 {
            break;
        }
        let take = chunk.min(read.max_bytes.saturating_sub(out.len()));
        out.extend_from_slice(&buffer[..take]);
        if out.len() >= read.max_bytes {
            break;
        }
        if read.idle_ms == 0 {
            break;
        }
    }
    Ok(out)
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

pub fn read_opts_from_spec(spec: &SocketProbeSpec) -> ReadOpts {
    ReadOpts {
        max_bytes: spec.read_max as usize,
        idle_ms: spec.read_idle_ms,
    }
}
