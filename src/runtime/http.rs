use std::collections::HashMap;
use std::time::Instant;

use futures::StreamExt;
use reqwest::header::HeaderMap;
use reqwest::{Client, Method, RequestBuilder};

use crate::contract::HttpMethod;
use crate::runtime::body::{object_to_form, object_to_json, object_to_multipart};
use crate::runtime::bytes::decode_hex;
use crate::runtime::context::VariableValue;
use crate::runtime::duration::parse_duration;
use crate::runtime::error::RuntimeError;
use crate::runtime::interpolate::interpolate;
use crate::runtime::response::HttpResponse;
use crate::runtime::spec::HttpRequestSpec;

pub async fn execute_http(
    client: &Client,
    base_url: &str,
    spec: &HttpRequestSpec,
    variables: &HashMap<String, VariableValue>,
    max_response_bytes: usize,
) -> Result<HttpResponse, RuntimeError> {
    let raw_path = spec.path.as_str();
    let path = interpolate(raw_path, variables)?;
    let url = join_url(base_url, raw_path, &path)?;
    let method = to_reqwest_method(&spec.method);
    let timeout = spec.timeout.as_deref().map(parse_duration).transpose()?;

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

    // RFC 6265 §5.4 requires all cookies to ride in a single `Cookie:` header
    // joined by `"; "`. reqwest's `.header()` appends, so emitting one call
    // per cookie produced multiple `Cookie:` headers — accepted leniently by
    // some servers, rejected outright by others. Build one joined string.
    if !spec.cookies.is_empty() {
        let mut parts = Vec::with_capacity(spec.cookies.len());
        for (name, value) in &spec.cookies {
            let name = interpolate(name, variables)?;
            let value = interpolate(value, variables)?;
            parts.push(format!("{name}={value}"));
        }
        builder = builder.header("cookie", parts.join("; "));
    }

    if !spec.queries.is_empty() {
        let pairs: Vec<(String, String)> = spec
            .queries
            .iter()
            .map(|(name, value)| {
                Ok((
                    interpolate(name, variables)?,
                    interpolate(value, variables)?,
                ))
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
        HttpMethod::Head => Method::HEAD,
        HttpMethod::Options => Method::OPTIONS,
    }
}

/// Resolve the request URL relative to the scan target (`base`).
///
/// `raw_path` is the path written in the script (pre-interpolation);
/// `resolved_path` is the same string after `{{ var }}` substitution.
/// We allow absolute URLs *if and only if* the script itself wrote one —
/// allowing interpolation to switch the scheme/host opens an SSRF where a
/// previously-extracted variable can redirect later probes to internal
/// services (`http://169.254.169.254/...`, `http://localhost:6379/...`).
fn join_url(base: &str, raw_path: &str, resolved_path: &str) -> Result<String, RuntimeError> {
    let raw_is_absolute = is_absolute_http_url(raw_path);
    let resolved_is_absolute = is_absolute_http_url(resolved_path);
    if raw_is_absolute {
        return Ok(resolved_path.to_string());
    }
    if resolved_is_absolute {
        // Interpolation produced an absolute URL from a relative template —
        // a hostname swap by variable. Reject.
        return Err(RuntimeError::Other(format!(
            "interpolated path switched to absolute URL; refusing as SSRF guard: {resolved_path}"
        )));
    }
    let base = base.trim_end_matches('/');
    let path = if resolved_path.starts_with('/') {
        resolved_path.to_string()
    } else {
        format!("/{resolved_path}")
    };
    Ok(format!("{base}{path}"))
}

fn is_absolute_http_url(value: &str) -> bool {
    let lower = value.trim_start();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// Convert reqwest's `HeaderMap` into a `HashMap<String, String>` for
/// downstream matchers. HTTP allows multi-valued headers (most notably
/// `Set-Cookie`, also `WWW-Authenticate`, `Link`, etc.); reqwest's
/// `HeaderMap` keeps them as separate entries, but matchers expect one
/// string per header name. We collapse duplicates by joining with `", "`,
/// which is the RFC 7230 §3.2.2 combining rule for the headers it applies
/// to; `Set-Cookie` is the documented exception, but matchers operate by
/// substring search ("`HttpOnly`", "`Secure`", domain names) which still
/// works correctly against a joined string.
fn flatten_headers(headers: &HeaderMap) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for (name, value) in headers.iter() {
        let Ok(text) = value.to_str() else { continue };
        match map.entry(name.as_str().to_string()) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                let combined = format!("{}, {}", e.get(), text);
                e.insert(combined);
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(text.to_string());
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn join_url_appends_relative_path() {
        let url = join_url("http://t.example", "/api", "/api").unwrap();
        assert_eq!(url, "http://t.example/api");
    }

    #[test]
    fn join_url_handles_path_without_leading_slash() {
        let url = join_url("http://t.example", "api", "api").unwrap();
        assert_eq!(url, "http://t.example/api");
    }

    #[test]
    fn join_url_strips_trailing_base_slash() {
        let url = join_url("http://t.example/", "/api", "/api").unwrap();
        assert_eq!(url, "http://t.example/api");
    }

    #[test]
    fn join_url_allows_explicitly_absolute_path() {
        // Script writer wrote a full URL into the path — that's an explicit
        // opt-in, so we honor it (e.g. probing a different origin during a
        // multi-host check).
        let url = join_url(
            "http://t.example",
            "https://other.example/x",
            "https://other.example/x",
        )
        .unwrap();
        assert_eq!(url, "https://other.example/x");
    }

    #[test]
    fn join_url_rejects_interpolated_scheme_switch() {
        // The template is a relative path, but a variable expanded into a
        // full URL. That's an SSRF vector — refuse.
        let err = join_url(
            "http://t.example",
            "/api/{{ next }}",
            "http://169.254.169.254/latest/meta-data",
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("SSRF"), "expected SSRF guard, got: {msg}");
    }

    #[test]
    fn join_url_rejects_interpolated_localhost_redirect() {
        let err = join_url(
            "http://t.example",
            "{{ extracted }}",
            "http://localhost:6379/info",
        )
        .unwrap_err();
        assert!(err.to_string().contains("SSRF"));
    }

    #[test]
    fn flatten_headers_combines_duplicates() {
        let mut headers = HeaderMap::new();
        headers.append("set-cookie", HeaderValue::from_static("a=1"));
        headers.append("set-cookie", HeaderValue::from_static("b=2"));
        let flat = flatten_headers(&headers);
        let cookie = flat.get("set-cookie").expect("set-cookie");
        // Joined form so substring matchers on cookie attributes still work.
        assert!(cookie.contains("a=1"));
        assert!(cookie.contains("b=2"));
    }

    #[test]
    fn flatten_headers_keeps_single_value_intact() {
        let mut headers = HeaderMap::new();
        headers.insert("x-foo", HeaderValue::from_static("bar"));
        let flat = flatten_headers(&headers);
        assert_eq!(flat.get("x-foo").map(String::as_str), Some("bar"));
    }
}
