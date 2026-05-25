use std::collections::HashMap;

use reqwest::multipart::{Form, Part};

use crate::runtime::bytes::decode_hex;
use crate::runtime::context::VariableValue;
use crate::runtime::error::RuntimeError;
use crate::runtime::interpolate::{interpolate, resolve_scalar};
use crate::contract::{BodyValue, InlinePart, InlinePartBody, ObjectBody};

pub fn object_to_json(
    body: &ObjectBody,
    variables: &HashMap<String, VariableValue>,
) -> Result<String, RuntimeError> {
    let mut parts = Vec::new();
    for (key, value) in &body.pairs {
        let key = interpolate(key, variables)?;
        let rendered = render_body_value(value, variables)?;
        parts.push(format!("\"{}\": {}", escape_json(&key), rendered));
    }
    Ok(format!("{{{}}}", parts.join(", ")))
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

fn render_body_value(
    value: &BodyValue,
    variables: &HashMap<String, VariableValue>,
) -> Result<String, RuntimeError> {
    Ok(match value {
        BodyValue::String(text) => {
            format!("\"{}\"", escape_json(&interpolate(text, variables)?))
        }
        BodyValue::Interpolation(name) => {
            format!("\"{}\"", escape_json(&resolve_scalar(name, variables)?))
        }
        BodyValue::Object(nested) => object_to_json(nested, variables)?,
        BodyValue::Bytes(_) | BodyValue::Part(_) => "\"<binary>\"".into(),
    })
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

fn escape_json(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}
