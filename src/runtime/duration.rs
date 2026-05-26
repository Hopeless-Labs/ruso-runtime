use std::time::Duration;

use crate::runtime::error::RuntimeError;

/// Parse a duration string with one of the supported suffixes:
///
/// | suffix | unit           |
/// |--------|----------------|
/// | `ms`   | milliseconds   |
/// | `s`    | seconds        |
/// | `m`    | minutes        |
/// | `h`    | hours          |
/// | `d`    | days           |
///
/// Whitespace between the number and the suffix is allowed. Earlier
/// revisions only supported `ms` and `s`, which forced `5m` to be
/// written as `300s` and made script-level timeouts awkward.
pub fn parse_duration(input: &str) -> Result<Duration, RuntimeError> {
    let trimmed = input.trim();
    let (digits, unit) =
        split_suffix(trimmed).ok_or_else(|| RuntimeError::InvalidDuration(input.to_string()))?;
    let value: u64 = digits
        .trim()
        .parse()
        .map_err(|_| RuntimeError::InvalidDuration(input.to_string()))?;
    let scaled = match unit {
        "ms" => Duration::from_millis(value),
        "s" => Duration::from_secs(value),
        "m" => Duration::from_secs(value.saturating_mul(60)),
        "h" => Duration::from_secs(value.saturating_mul(3600)),
        "d" => Duration::from_secs(value.saturating_mul(86_400)),
        _ => return Err(RuntimeError::InvalidDuration(input.to_string())),
    };
    Ok(scaled)
}

/// Split `"500ms"` into `("500", "ms")`. Returns `None` if no recognised
/// suffix is present. Longest-suffix match so `ms` wins over `s`.
fn split_suffix(input: &str) -> Option<(&str, &str)> {
    for suffix in ["ms", "s", "m", "h", "d"] {
        if let Some(stripped) = input.strip_suffix(suffix) {
            return Some((stripped, suffix));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ms_unit() {
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
    }

    #[test]
    fn s_unit() {
        assert_eq!(parse_duration("3s").unwrap(), Duration::from_secs(3));
    }

    #[test]
    fn m_unit() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn h_unit() {
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn d_unit() {
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86_400));
    }

    #[test]
    fn ms_wins_over_s_suffix() {
        // `500ms` must not be parsed as `500m` + leftover `s`.
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn rejects_missing_suffix() {
        assert!(parse_duration("42").is_err());
    }

    #[test]
    fn rejects_unknown_suffix() {
        assert!(parse_duration("5z").is_err());
    }

    #[test]
    fn rejects_negative_value() {
        assert!(parse_duration("-1s").is_err());
    }
}
