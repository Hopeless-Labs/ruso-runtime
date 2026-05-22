use regex::Regex;

use crate::runtime::error::RuntimeError;
use crate::runtime::response::ProbeResponse;
use crate::contract::{
    CmpOp, CmpValue, FieldKind, MatchPredicate, QualifiedMatch,
};

pub fn evaluate(matcher: &QualifiedMatch, response: &ProbeResponse) -> Result<bool, RuntimeError> {
    let field = &matcher.field;
    let predicate = &matcher.predicate;

    match (&field.kind, predicate) {
        (FieldKind::Status, MatchPredicate::Compare { op, value }) => {
            let http = response.as_http().map_err(|_| RuntimeError::WrongProbeKind {
                name: field.target.clone(),
            })?;
            Ok(compare_number(http.status as u64, *op, value)?)
        }
        (FieldKind::Body, MatchPredicate::Contains(text)) => {
            let http = response.as_http().map_err(|_| RuntimeError::WrongProbeKind {
                name: field.target.clone(),
            })?;
            Ok(http.body.contains(text))
        }
        (FieldKind::Body, MatchPredicate::NotContains(text)) => {
            let http = response.as_http().map_err(|_| RuntimeError::WrongProbeKind {
                name: field.target.clone(),
            })?;
            Ok(!http.body.contains(text))
        }
        (FieldKind::Body, MatchPredicate::Regex(pattern)) => {
            let http = response.as_http().map_err(|_| RuntimeError::WrongProbeKind {
                name: field.target.clone(),
            })?;
            let regex = Regex::new(pattern)?;
            Ok(regex.is_match(&http.body))
        }
        (FieldKind::Header(name), MatchPredicate::Contains(text)) => {
            let http = response.as_http().map_err(|_| RuntimeError::WrongProbeKind {
                name: field.target.clone(),
            })?;
            let header = find_header(&http.headers, name);
            Ok(header.contains(text))
        }
        (FieldKind::Header(name), MatchPredicate::NotContains(text)) => {
            let http = response.as_http().map_err(|_| RuntimeError::WrongProbeKind {
                name: field.target.clone(),
            })?;
            let header = find_header(&http.headers, name);
            Ok(!header.contains(text))
        }
        (FieldKind::ResponseTime, MatchPredicate::Compare { op, value }) => {
            let http = response.as_http().map_err(|_| RuntimeError::WrongProbeKind {
                name: field.target.clone(),
            })?;
            let actual_ms = http.elapsed.as_millis() as u64;
            compare_duration_ms(actual_ms, *op, value)
        }
        (FieldKind::ResponseSize, MatchPredicate::Compare { op, value }) => {
            let http = response.as_http().map_err(|_| RuntimeError::WrongProbeKind {
                name: field.target.clone(),
            })?;
            Ok(compare_number(http.body.len() as u64, *op, value)?)
        }
        (FieldKind::Answer, MatchPredicate::Contains(text)) => {
            let dns = response.as_dns_resolve().map_err(|_| RuntimeError::WrongProbeKind {
                name: field.target.clone(),
            })?;
            Ok(dns.answers.join(" ").contains(text))
        }
        (FieldKind::Answer, MatchPredicate::NotContains(text)) => {
            let dns = response.as_dns_resolve().map_err(|_| RuntimeError::WrongProbeKind {
                name: field.target.clone(),
            })?;
            Ok(!dns.answers.join(" ").contains(text))
        }
        (FieldKind::Response | FieldKind::Banner, MatchPredicate::Contains(_))
        | (FieldKind::Response | FieldKind::Banner, MatchPredicate::NotContains(_)) => {
            let data = socket_data(response).map_err(|_| RuntimeError::WrongProbeKind {
                name: field.target.clone(),
            })?;
            match predicate {
                MatchPredicate::Contains(text) => Ok(data.contains(text)),
                MatchPredicate::NotContains(text) => Ok(!data.contains(text)),
                _ => unreachable!(),
            }
        }
        (FieldKind::Response | FieldKind::Banner, MatchPredicate::Regex(pattern)) => {
            let data = socket_data(response).map_err(|_| RuntimeError::WrongProbeKind {
                name: field.target.clone(),
            })?;
            let regex = Regex::new(pattern)?;
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
    responses: &std::collections::HashMap<String, ProbeResponse>,
) -> Result<bool, RuntimeError> {
    for matcher in matchers {
        let response = responses
            .get(&matcher.field.target)
            .ok_or_else(|| RuntimeError::UnknownTarget(matcher.field.target.clone()))?;
        if !evaluate(matcher, response)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn evaluate_any(
    matchers: &[QualifiedMatch],
    responses: &std::collections::HashMap<String, ProbeResponse>,
) -> Result<bool, RuntimeError> {
    for matcher in matchers {
        let response = responses
            .get(&matcher.field.target)
            .ok_or_else(|| RuntimeError::UnknownTarget(matcher.field.target.clone()))?;
        if evaluate(matcher, response)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn socket_data<'a>(response: &'a ProbeResponse) -> Result<&'a str, ()> {
    Ok(&response.as_socket()?.data)
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
