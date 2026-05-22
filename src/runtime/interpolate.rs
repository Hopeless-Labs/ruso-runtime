use std::collections::HashMap;

pub fn interpolate(template: &str, variables: &HashMap<String, String>) -> String {
    let mut output = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'{' && index + 1 < bytes.len() && bytes[index + 1] == b'{' {
            if let Some((end, name)) = parse_placeholder(&template[index + 2..]) {
                let value = variables.get(&name).cloned().unwrap_or_default();
                output.push_str(&value);
                index += 2 + end;
                continue;
            }
        }
        let ch = template[index..].chars().next().unwrap();
        output.push(ch);
        index += ch.len_utf8();
    }

    output
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

    #[test]
    fn replaces_variables() {
        let mut vars = HashMap::new();
        vars.insert("token".into(), "abc".into());
        assert_eq!(
            interpolate("Bearer {{ token }}", &vars),
            "Bearer abc"
        );
    }
}
