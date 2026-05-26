use std::collections::HashMap;

use reqwest::multipart::{Form, Part};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::contract::{BodyValue, InlinePart, InlinePartBody, ObjectBody};
use crate::runtime::bytes::decode_hex;
use crate::runtime::context::VariableValue;
use crate::runtime::error::RuntimeError;
use crate::runtime::interpolate::{interpolate, resolve_scalar};

pub fn object_to_json(
    body: &ObjectBody,
    variables: &HashMap<String, VariableValue>,
) -> Result<String, RuntimeError> {
    let value = object_to_json_value(body, variables)?;
    Ok(value.to_string())
}

fn object_to_json_value(
    body: &ObjectBody,
    variables: &HashMap<String, VariableValue>,
) -> Result<JsonValue, RuntimeError> {
    let mut map = JsonMap::with_capacity(body.pairs.len());
    for (key, value) in &body.pairs {
        let key = interpolate(key, variables)?;
        map.insert(key, body_value_to_json(value, variables)?);
    }
    Ok(JsonValue::Object(map))
}

/// Render a [`BodyValue`] into a JSON-typed [`JsonValue`].
///
/// Rendering goes through `serde_json` rather than concatenating strings so
/// every interpolated value is escaped correctly: an extracted variable
/// containing `"` or a control char can no longer break out of the JSON
/// string context (the prior `escape_json` only handled `\ " \n \r \t`,
/// missing other control chars and leaving JSON injection on the table).
fn body_value_to_json(
    value: &BodyValue,
    variables: &HashMap<String, VariableValue>,
) -> Result<JsonValue, RuntimeError> {
    Ok(match value {
        BodyValue::String(text) => JsonValue::String(interpolate(text, variables)?),
        BodyValue::Interpolation(name) => JsonValue::String(resolve_scalar(name, variables)?),
        BodyValue::Object(nested) => object_to_json_value(nested, variables)?,
        // Binary parts cannot live in a JSON document; surface a sentinel
        // string so the encoded request still parses, matching the previous
        // "<binary>" placeholder behaviour.
        BodyValue::Bytes(_) | BodyValue::Part(_) => JsonValue::String("<binary>".into()),
    })
}

pub fn object_to_form(
    body: &ObjectBody,
    variables: &HashMap<String, VariableValue>,
) -> Result<Vec<(String, String)>, RuntimeError> {
    body.pairs
        .iter()
        .map(|(key, value)| {
            Ok((
                interpolate(key, variables)?,
                render_body_value_string(value, variables)?,
            ))
        })
        .collect()
}

/// Build `multipart/form-data` from inline script content (no filesystem reads).
pub fn object_to_multipart(
    body: &ObjectBody,
    variables: &HashMap<String, VariableValue>,
) -> Result<Form, RuntimeError> {
    let mut form = Form::new();
    for (key, value) in &body.pairs {
        let field = interpolate(key, variables)?;
        form = match value {
            BodyValue::String(text) => form.text(field, interpolate(text, variables)?),
            BodyValue::Interpolation(name) => form.text(field, resolve_scalar(name, variables)?),
            BodyValue::Bytes(hex) => {
                let bytes = decode_hex(&interpolate(hex, variables)?)?;
                form.part(field, Part::bytes(bytes))
            }
            BodyValue::Part(part) => {
                let (bytes, filename) = part_bytes(part, variables)?;
                let mut p = Part::bytes(bytes);
                if let Some(name) = filename {
                    p = p.file_name(name);
                }
                form.part(field, p)
            }
            BodyValue::Object(_) => {
                return Err(RuntimeError::Other(
                    "nested objects are not supported in multipart blocks".into(),
                ));
            }
        };
    }
    Ok(form)
}

fn part_bytes(
    part: &InlinePart,
    variables: &HashMap<String, VariableValue>,
) -> Result<(Vec<u8>, Option<String>), RuntimeError> {
    let filename = part
        .filename
        .as_ref()
        .map(|name| interpolate(name, variables))
        .transpose()?;
    let bytes = match &part.body {
        InlinePartBody::Text(text) => interpolate(text, variables)?.into_bytes(),
        InlinePartBody::Bytes(hex) => decode_hex(&interpolate(hex, variables)?)?,
    };
    Ok((bytes, filename))
}

fn render_body_value_string(
    value: &BodyValue,
    variables: &HashMap<String, VariableValue>,
) -> Result<String, RuntimeError> {
    Ok(match value {
        BodyValue::String(text) => interpolate(text, variables)?,
        BodyValue::Interpolation(name) => resolve_scalar(name, variables)?,
        BodyValue::Object(nested) => object_to_json(nested, variables)?,
        BodyValue::Bytes(_) | BodyValue::Part(_) => String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::BodyValue;

    fn vars(entries: &[(&str, &str)]) -> HashMap<String, VariableValue> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), VariableValue::String((*v).to_string())))
            .collect()
    }

    #[test]
    fn json_escapes_quote_in_value() {
        let body = ObjectBody {
            pairs: vec![("x".into(), BodyValue::Interpolation("payload".into()))],
        };
        let vars = vars(&[("payload", "a\"b")]);
        let json = object_to_json(&body, &vars).unwrap();
        // Round-trip through serde_json to confirm it's valid JSON and the
        // value is *not* injected as JSON syntax.
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["x"], serde_json::json!("a\"b"));
    }

    #[test]
    fn json_escapes_control_chars_that_old_escape_missed() {
        let body = ObjectBody {
            pairs: vec![("ctrl".into(), BodyValue::Interpolation("payload".into()))],
        };
        // \x08 (backspace) and \x0c (form feed) — both legal JSON but the
        // old hand-rolled escape only handled \n\r\t.
        let vars = vars(&[("payload", "\u{0008}\u{000c}")]);
        let json = object_to_json(&body, &vars).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ctrl"], serde_json::json!("\u{0008}\u{000c}"));
    }

    #[test]
    fn json_prevents_injection_via_quotes_and_braces() {
        // Regression for H4: a hostile target that fills a variable with
        // `","admin":true,"x":"` must not be able to alter the request shape.
        let body = ObjectBody {
            pairs: vec![("note".into(), BodyValue::Interpolation("payload".into()))],
        };
        let vars = vars(&[("payload", "\",\"admin\":true,\"x\":\"")]);
        let json = object_to_json(&body, &vars).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        // The payload must remain a single string property; no `admin` key.
        assert!(parsed.get("admin").is_none());
        assert!(parsed["note"].as_str().unwrap().contains("admin"));
    }

    #[test]
    fn json_nested_object_keeps_structure() {
        let body = ObjectBody {
            pairs: vec![(
                "outer".into(),
                BodyValue::Object(ObjectBody {
                    pairs: vec![("inner".into(), BodyValue::String("v".into()))],
                }),
            )],
        };
        let json = object_to_json(&body, &HashMap::new()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["outer"]["inner"], "v");
    }
}
