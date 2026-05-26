use regex::Regex;
use regex::bytes::Regex as BytesRegex;

use crate::contract::{CmpOp, CmpValue, FieldKind, MatchPredicate, QualifiedMatch};
use crate::runtime::error::RuntimeError;
use crate::runtime::response::ProbeResponse;

/// Pre-compiled regex for a single matcher slot. Aligned by index with
/// `BytecodeProgram::matchers` so the executor can compile every regex once
/// up-front and reuse it across every run / every loop iteration.
#[derive(Debug, Clone)]
pub enum CompiledMatcherRegex {
    /// Matcher does not use `regex` (Compare/Contains/NotContains/...), or its
    /// field kind has no regex variant.
    None,
    /// Regex against an HTTP body (`http_probe.body regex '...'`). The body
    /// is decoded as a `String`, so the text-flavor `Regex` is fine.
    HttpBody(Regex),
    /// Regex against raw socket bytes (`tcp_probe.response regex '...'`).
    /// Uses the `bytes` flavor so patterns can match non-UTF-8 payloads.
    SocketBytes(BytesRegex),
}

impl CompiledMatcherRegex {
    /// Compile the regex stored in `matcher` if its predicate is `Regex(...)`,
    /// dispatching to text vs bytes flavor based on field kind.
    pub fn compile(matcher: &QualifiedMatch) -> Result<Self, RuntimeError> {
        match (&matcher.field.kind, &matcher.predicate) {
            (FieldKind::Body, MatchPredicate::Regex(pattern)) => {
                Ok(Self::HttpBody(Regex::new(pattern)?))
            }
            (FieldKind::Response | FieldKind::Banner, MatchPredicate::Regex(pattern)) => {
                Ok(Self::SocketBytes(BytesRegex::new(pattern)?))
            }
            _ => Ok(Self::None),
        }
    }
}

/// Evaluate a single matcher against a probe response, using a pre-compiled
/// regex when the predicate is `Regex(...)`.
pub fn evaluate(
    matcher: &QualifiedMatch,
    response: &ProbeResponse,
    compiled_regex: &CompiledMatcherRegex,
) -> Result<bool, RuntimeError> {
    let field = &matcher.field;
    let predicate = &matcher.predicate;

    match (&field.kind, predicate) {
        (FieldKind::Status, MatchPredicate::Compare { op, value }) => {
            let http = response
                .as_http()
                .map_err(|_| RuntimeError::WrongProbeKind {
                    name: field.target.clone(),
                })?;
            Ok(compare_number(http.status as u64, *op, value)?)
        }
        (FieldKind::Body, MatchPredicate::Contains(text)) => {
            let http = response
                .as_http()
                .map_err(|_| RuntimeError::WrongProbeKind {
                    name: field.target.clone(),
                })?;
            Ok(http.body.contains(text))
        }
        (FieldKind::Body, MatchPredicate::NotContains(text)) => {
            let http = response
                .as_http()
                .map_err(|_| RuntimeError::WrongProbeKind {
                    name: field.target.clone(),
                })?;
            Ok(!http.body.contains(text))
        }
        (FieldKind::Body, MatchPredicate::Regex(_)) => {
            let http = response
                .as_http()
                .map_err(|_| RuntimeError::WrongProbeKind {
                    name: field.target.clone(),
                })?;
            let CompiledMatcherRegex::HttpBody(regex) = compiled_regex else {
                return Err(RuntimeError::Other(
                    "regex matcher missing pre-compiled http body regex".into(),
                ));
            };
            Ok(regex.is_match(&http.body))
        }
        (FieldKind::Header(name), MatchPredicate::Contains(text)) => {
            let http = response
                .as_http()
                .map_err(|_| RuntimeError::WrongProbeKind {
                    name: field.target.clone(),
                })?;
            let header = find_header(&http.headers, name);
            Ok(header.contains(text))
        }
        (FieldKind::Header(name), MatchPredicate::NotContains(text)) => {
            let http = response
                .as_http()
                .map_err(|_| RuntimeError::WrongProbeKind {
                    name: field.target.clone(),
                })?;
            let header = find_header(&http.headers, name);
            Ok(!header.contains(text))
        }
        (FieldKind::ResponseTime, MatchPredicate::Compare { op, value }) => {
            let http = response
                .as_http()
                .map_err(|_| RuntimeError::WrongProbeKind {
                    name: field.target.clone(),
                })?;
            let actual_ms = http.elapsed.as_millis() as u64;
            compare_duration_ms(actual_ms, *op, value)
        }
        (FieldKind::ResponseSize, MatchPredicate::Compare { op, value }) => {
            let http = response
                .as_http()
                .map_err(|_| RuntimeError::WrongProbeKind {
                    name: field.target.clone(),
                })?;
            Ok(compare_number(http.body.len() as u64, *op, value)?)
        }
        (FieldKind::Answer, MatchPredicate::Contains(text)) => {
            let dns = response
                .as_dns_resolve()
                .map_err(|_| RuntimeError::WrongProbeKind {
                    name: field.target.clone(),
                })?;
            Ok(dns.answers.join(" ").contains(text))
        }
        (FieldKind::Answer, MatchPredicate::NotContains(text)) => {
            let dns = response
                .as_dns_resolve()
                .map_err(|_| RuntimeError::WrongProbeKind {
                    name: field.target.clone(),
                })?;
            Ok(!dns.answers.join(" ").contains(text))
        }
        (FieldKind::Response | FieldKind::Banner, MatchPredicate::Contains(_))
        | (FieldKind::Response | FieldKind::Banner, MatchPredicate::NotContains(_)) => {
            let data = socket_bytes(response).map_err(|_| RuntimeError::WrongProbeKind {
                name: field.target.clone(),
            })?;
            match predicate {
                MatchPredicate::Contains(text) => Ok(bytes_contains(data, text.as_bytes())),
                MatchPredicate::NotContains(text) => Ok(!bytes_contains(data, text.as_bytes())),
                _ => unreachable!(),
            }
        }
        (FieldKind::Response | FieldKind::Banner, MatchPredicate::Regex(_)) => {
            let data = socket_bytes(response).map_err(|_| RuntimeError::WrongProbeKind {
                name: field.target.clone(),
            })?;
            // Use the bytes regex flavor so patterns can target non-UTF-8
            // banners (binary protocols, control bytes, etc.).
            let CompiledMatcherRegex::SocketBytes(regex) = compiled_regex else {
                return Err(RuntimeError::Other(
                    "regex matcher missing pre-compiled socket bytes regex".into(),
                ));
            };
            Ok(regex.is_match(data))
        }
        _ => Err(RuntimeError::Other(format!(
            "unsupported matcher for {:?}",
            field.kind
        ))),
    }
}

pub fn evaluate_all(
    matchers: &[QualifiedMatch],
    compiled: &[CompiledMatcherRegex],
    responses: &std::collections::HashMap<String, ProbeResponse>,
) -> Result<bool, RuntimeError> {
    for (matcher, regex) in matchers.iter().zip(compiled.iter()) {
        let response = responses
            .get(&matcher.field.target)
            .ok_or_else(|| RuntimeError::UnknownTarget(matcher.field.target.clone()))?;
        if !evaluate(matcher, response, regex)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn evaluate_any(
    matchers: &[QualifiedMatch],
    compiled: &[CompiledMatcherRegex],
    responses: &std::collections::HashMap<String, ProbeResponse>,
) -> Result<bool, RuntimeError> {
    for (matcher, regex) in matchers.iter().zip(compiled.iter()) {
        let response = responses
            .get(&matcher.field.target)
            .ok_or_else(|| RuntimeError::UnknownTarget(matcher.field.target.clone()))?;
        if evaluate(matcher, response, regex)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn socket_bytes(response: &ProbeResponse) -> Result<&[u8], ()> {
    Ok(&response.as_socket()?.data)
}

/// Byte-wise substring search. Returns true if `haystack` contains `needle`
/// as a contiguous slice. Mirrors `str::contains` semantics: empty needle
/// matches anywhere (so the result is `true`).
fn bytes_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn find_header(headers: &std::collections::HashMap<String, String>, name: &str) -> String {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .unwrap_or("")
        .to_string()
}

fn compare_number(actual: u64, op: CmpOp, value: &CmpValue) -> Result<bool, RuntimeError> {
    let expected = match value {
        CmpValue::Number(n) => *n,
        CmpValue::String(s) => s.parse().map_err(|_| {
            RuntimeError::Other(format!("expected numeric comparison, got string: {s}"))
        })?,
        CmpValue::Duration(_) => {
            return Err(RuntimeError::Other(
                "duration not valid for numeric field".into(),
            ));
        }
    };
    Ok(match op {
        CmpOp::Eq => actual == expected,
        CmpOp::Ne => actual != expected,
        CmpOp::Lt => actual < expected,
        CmpOp::Gt => actual > expected,
        CmpOp::Le => actual <= expected,
        CmpOp::Ge => actual >= expected,
    })
}

fn compare_duration_ms(actual_ms: u64, op: CmpOp, value: &CmpValue) -> Result<bool, RuntimeError> {
    use crate::runtime::duration::parse_duration;

    let expected = match value {
        CmpValue::Duration(s) => parse_duration(s)?.as_millis() as u64,
        CmpValue::Number(n) => *n,
        CmpValue::String(s) => parse_duration(s)?.as_millis() as u64,
    };
    Ok(match op {
        CmpOp::Eq => actual_ms == expected,
        CmpOp::Ne => actual_ms != expected,
        CmpOp::Lt => actual_ms < expected,
        CmpOp::Gt => actual_ms > expected,
        CmpOp::Le => actual_ms <= expected,
        CmpOp::Ge => actual_ms >= expected,
    })
}

#[cfg(test)]
mod tests {
    use super::{CompiledMatcherRegex, bytes_contains, evaluate};
    use crate::contract::{FieldKind, MatchPredicate, QualifiedField, QualifiedMatch};
    use crate::runtime::response::{ProbeResponse, SocketResponse};

    #[test]
    fn bytes_contains_matches_ascii() {
        assert!(bytes_contains(b"hello world", b"world"));
        assert!(!bytes_contains(b"hello world", b"xyz"));
    }

    #[test]
    fn bytes_contains_matches_non_utf8() {
        let haystack = &[0x00, 0xff, 0xab, 0xcd, 0xef][..];
        assert!(bytes_contains(haystack, &[0xab, 0xcd]));
        assert!(!bytes_contains(haystack, &[0xcd, 0xab]));
    }

    #[test]
    fn bytes_contains_empty_needle() {
        assert!(bytes_contains(b"anything", b""));
    }

    #[test]
    fn bytes_contains_needle_longer_than_haystack() {
        assert!(!bytes_contains(b"hi", b"hello"));
    }

    fn socket_response_with(data: Vec<u8>) -> ProbeResponse {
        ProbeResponse::Socket(SocketResponse {
            host: "h".into(),
            port: 1,
            data,
        })
    }

    fn matcher_response_contains(needle: &str) -> QualifiedMatch {
        QualifiedMatch {
            field: QualifiedField {
                target: "p".into(),
                kind: FieldKind::Response,
            },
            predicate: MatchPredicate::Contains(needle.into()),
        }
    }

    #[test]
    fn evaluate_matches_binary_banner_through_response_field() {
        // Real-world case: SSH server banner contains non-UTF-8 sequences in
        // some protocol versions. Before the bytes refactor, lossy decoding
        // would mangle this and the match would silently fail.
        let banner: Vec<u8> = vec![
            b'S', b'S', b'H', b'-', b'2', b'.', b'0', b'-', 0xff, 0xab, b'\r', b'\n',
        ];
        let response = socket_response_with(banner);
        let matcher = matcher_response_contains("SSH-2.0-");
        // Non-regex predicates don't need a compiled regex; pass None-variant.
        assert!(evaluate(&matcher, &response, &CompiledMatcherRegex::None).unwrap());
    }

    #[test]
    fn evaluate_regex_on_binary_banner() {
        // Banner has non-UTF-8 bytes (0xff). The regex anchors literal text
        // around them — pre-refactor the lossy String would have replaced
        // 0xff with U+FFFD and broken any pattern positioned against it.
        // Use `(?-u:.)` to opt into non-Unicode `.` that matches any byte.
        let banner: Vec<u8> = vec![0x00, b'A', b'B', 0xff, b'C'];
        let response = socket_response_with(banner);
        let matcher = QualifiedMatch {
            field: QualifiedField {
                target: "p".into(),
                kind: FieldKind::Response,
            },
            predicate: MatchPredicate::Regex(r"AB(?-u:.)C".into()),
        };
        let compiled = CompiledMatcherRegex::compile(&matcher).unwrap();
        assert!(evaluate(&matcher, &response, &compiled).unwrap());
    }

    #[test]
    fn compile_returns_none_for_non_regex_predicate() {
        let matcher = matcher_response_contains("anything");
        assert!(matches!(
            CompiledMatcherRegex::compile(&matcher).unwrap(),
            CompiledMatcherRegex::None
        ));
    }

    #[test]
    fn compile_dispatches_http_body_vs_socket_bytes() {
        let http = QualifiedMatch {
            field: QualifiedField {
                target: "h".into(),
                kind: FieldKind::Body,
            },
            predicate: MatchPredicate::Regex("ok".into()),
        };
        assert!(matches!(
            CompiledMatcherRegex::compile(&http).unwrap(),
            CompiledMatcherRegex::HttpBody(_)
        ));

        let sock = QualifiedMatch {
            field: QualifiedField {
                target: "h".into(),
                kind: FieldKind::Banner,
            },
            predicate: MatchPredicate::Regex("ok".into()),
        };
        assert!(matches!(
            CompiledMatcherRegex::compile(&sock).unwrap(),
            CompiledMatcherRegex::SocketBytes(_)
        ));
    }

    #[test]
    fn compile_surfaces_invalid_regex_at_compile_time() {
        let matcher = QualifiedMatch {
            field: QualifiedField {
                target: "h".into(),
                kind: FieldKind::Body,
            },
            // Unbalanced bracket — invalid regex.
            predicate: MatchPredicate::Regex("[invalid".into()),
        };
        assert!(CompiledMatcherRegex::compile(&matcher).is_err());
    }
}
