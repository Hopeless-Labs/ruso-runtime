use std::collections::HashMap;

use crate::runtime::context::VariableValue;
use crate::runtime::error::RuntimeError;

/// Expand `{{ name }}` placeholders in `template` using the runtime's
/// variable map.
///
/// The previous implementation reissued `template[index..].chars().next()`
/// on each step, which is O(n) per call and turned the loop quadratic on
/// large bodies. We now walk a `char_indices` iterator once.
pub fn interpolate(
    template: &str,
    variables: &HashMap<String, VariableValue>,
) -> Result<String, RuntimeError> {
    let mut output = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut chars = template.char_indices().peekable();

    while let Some((index, ch)) = chars.next() {
        if ch == '{'
            && index + 1 < bytes.len()
            && bytes[index + 1] == b'{'
            && let Some((end, name)) = parse_placeholder(&template[index + 2..])
        {
            let value = resolve_scalar(&name, variables)?;
            output.push_str(&value);
            // Advance the iterator past the closing `}}`. `end` is the
            // byte offset (relative to `index+2`) just past the `}}`.
            let target = index + 2 + end;
            while let Some(&(next_index, _)) = chars.peek() {
                if next_index >= target {
                    break;
                }
                chars.next();
            }
            continue;
        }
        output.push(ch);
    }

    Ok(output)
}

pub fn resolve_scalar(
    name: &str,
    variables: &HashMap<String, VariableValue>,
) -> Result<String, RuntimeError> {
    match variables.get(name) {
        Some(VariableValue::String(value)) => Ok(value.clone()),
        Some(VariableValue::List(_)) => Err(RuntimeError::Other(format!(
            "variable {name} is a list and cannot be interpolated as a string"
        ))),
        None => Ok(String::new()),
    }
}

fn parse_placeholder(rest: &str) -> Option<(usize, String)> {
    let close = rest.find("}}")?;
    let name = rest[..close].trim();
    if name.is_empty() || !is_ident(name) {
        return None;
    }
    Some((close + 2, name.to_string()))
}

fn is_ident(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(entries: &[(&str, &str)]) -> HashMap<String, VariableValue> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), VariableValue::String((*v).to_string())))
            .collect()
    }

    #[test]
    fn replaces_variables() {
        let v = vars(&[("token", "abc")]);
        assert_eq!(interpolate("Bearer {{ token }}", &v).unwrap(), "Bearer abc");
    }

    #[test]
    fn handles_multi_byte_template_without_quadratic_blowup() {
        // Smoke test: a long UTF-8 template with no placeholders must
        // complete (the old impl ran O(n^2) but still finished — we want
        // a regression check that the new iterator is correct).
        let template = "日本語テキストが長く続きます".repeat(200);
        let out = interpolate(&template, &HashMap::new()).unwrap();
        assert_eq!(out, template);
    }

    #[test]
    fn missing_variable_expands_to_empty() {
        let out = interpolate("[{{ absent }}]", &HashMap::new()).unwrap();
        assert_eq!(out, "[]");
    }

    #[test]
    fn unclosed_placeholder_is_left_literal() {
        let out = interpolate("{{ token", &HashMap::new()).unwrap();
        assert_eq!(out, "{{ token");
    }

    #[test]
    fn list_variable_is_rejected() {
        let mut v = HashMap::new();
        v.insert(
            "items".to_string(),
            VariableValue::List(vec!["a".into(), "b".into()]),
        );
        assert!(interpolate("{{ items }}", &v).is_err());
    }
}
