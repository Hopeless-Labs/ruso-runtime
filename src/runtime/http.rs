use std::collections::HashMap;
use std::time::Instant;

use futures::StreamExt;
use reqwest::header::HeaderMap;
use reqwest::{Client, Method, RequestBuilder};

use crate::runtime::body::{object_to_form, object_to_json, object_to_multipart};
use crate::runtime::context::VariableValue;
use crate::runtime::bytes::decode_hex;
use crate::runtime::duration::parse_duration;
use crate::runtime::error::RuntimeError;
use crate::runtime::interpolate::interpolate;
use crate::runtime::response::HttpResponse;
use crate::runtime::spec::HttpRequestSpec;
use crate::contract::HttpMethod;

pub async fn execute_http(
    client: &Client,
    base_url: &str,
    spec: &HttpRequestSpec,
    variables: &HashMap<String, VariableValue>,
    max_response_bytes: usize,
) -> Result<HttpResponse, RuntimeError> {
    let path = interpolate(&spec.path, variables)?;
    let url = join_url(base_url, &path);
    let method = to_reqwest_method(&spec.method);
    let timeout = spec
        .timeout
        .as_deref()
        .map(parse_duration)
        .transpose()?;

    tracing::debug!(%url, ?method, "http request");

    let mut builder = client.request(method, url);
    if let Some(duration) = timeout {
        builder = builder.timeout(duration);
    }

    if let Some(agent) = &spec.user_agent {
        builder = builder.header("user-agent", interpolate(agent, variables)?);
    }

    for (name, value) in &spec.headers {
        builder = builder.header(
            interpolate(name, variables)?,
            interpolate(value, variables)?,
        );
    }

    for (name, value) in &spec.cookies {
        builder = builder.header(
            "cookie",
            format!(
                "{}={}",
                interpolate(name, variables)?,
                interpolate(value, variables)?
            ),
        );
    }

    if !spec.queries.is_empty() {
        let pairs: Vec<(String, String)> = spec
            .queries
            .iter()
            .map(|(name, value)| {
                Ok((interpolate(name, variables)?, interpolate(value, variables)?))
            })
            .collect::<Result<_, RuntimeError>>()?;
        builder = builder.query(&pairs);
    }

    builder = apply_body(builder, spec, variables)?;

    let started = Instant::now();
    let response = builder.send().await?;
    let elapsed = started.elapsed();
    let status = response.status().as_u16();
    let headers = flatten_headers(response.headers());
    let body = read_body_capped(response, max_response_bytes).await?;

    Ok(HttpResponse {
        status,
        headers,
        body,
        elapsed,
    })
}

/// Stream the response body into a buffer, stopping once `max_bytes` is
/// reached. Caps memory use against malicious targets returning multi-GB
/// payloads. The returned `String` is a lossy UTF-8 decode of the truncated
/// bytes — matchers that need byte-precise comparison should use socket
/// probes, not HTTP body.
async fn read_body_capped(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<String, RuntimeError> {
    if max_bytes == 0 {
        return Ok(String::new());
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let remaining = max_bytes.saturating_sub(buf.len());
        if remaining == 0 {
            tracing::warn!(
                limit = max_bytes,
                "http response body truncated at max_response_bytes"
            );
            break;
        }
        let take = chunk.len().min(remaining);
        buf.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            tracing::warn!(
                limit = max_bytes,
                "http response body truncated at max_response_bytes"
            );
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

pub fn build_client(
    default_timeout: Option<std::time::Duration>,
    follow_redirect: bool,
    verify_ssl: bool,
    proxy: Option<&str>,
) -> Result<Client, RuntimeError> {
    let mut builder = Client::builder();
    if let Some(timeout) = default_timeout {
        builder = builder.timeout(timeout);
    }
    builder = builder.redirect(if follow_redirect {
        reqwest::redirect::Policy::limited(10)
    } else {
        reqwest::redirect::Policy::none()
    });
    if !verify_ssl {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(proxy_url) = proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy_url)?);
    }
    Ok(builder.build()?)
}

/// Attach request body; first matching mode in the request block wins (see `http_spec`).
fn apply_body(
    builder: RequestBuilder,
    spec: &HttpRequestSpec,
    variables: &HashMap<String, VariableValue>,
) -> Result<RequestBuilder, RuntimeError> {
    if let Some(body) = &spec.json_body {
        let json = object_to_json(body, variables)?;
        return Ok(builder
            .header("content-type", "application/json")
            .body(json));
    }
    if let Some(body) = &spec.data_body {
        let form = object_to_form(body, variables)?;
        return Ok(builder.form(&form));
    }
    if let Some(raw) = &spec.raw_body {
        return Ok(builder.body(interpolate(raw, variables)?));
    }
    if let Some(body) = &spec.multipart_body {
        let form = object_to_multipart(body, variables)?;
        return Ok(builder.multipart(form));
    }
    if let Some(hex) = &spec.body_bytes {
        let bytes = decode_hex(&interpolate(hex, variables)?)?;
        return Ok(builder.body(bytes));
    }
    Ok(builder)
}

fn to_reqwest_method(method: &HttpMethod) -> Method {
    match method {
        HttpMethod::Get => Method::GET,
        HttpMethod::Post => Method::POST,
        HttpMethod::Put => Method::PUT,
        HttpMethod::Patch => Method::PATCH,
        HttpMethod::Delete => Method::DELETE,
    }
}

fn join_url(base: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    let base = base.trim_end_matches('/');
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    format!("{base}{path}")
}

fn flatten_headers(headers: &HeaderMap) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (name, value) in headers.iter() {
        if let Ok(text) = value.to_str() {
            map.insert(name.as_str().to_string(), text.to_string());
        }
    }
    map
}
