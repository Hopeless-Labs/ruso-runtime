use std::time::Duration;

use crate::runtime::error::RuntimeError;

pub fn parse_duration(input: &str) -> Result<Duration, RuntimeError> {
    let input = input.trim();
    if let Some(ms) = input.strip_suffix("ms") {
        let value: u64 = ms
            .trim()
            .parse()
            .map_err(|_| RuntimeError::InvalidDuration(input.to_string()))?;
        return Ok(Duration::from_millis(value));
    }
    if let Some(secs) = input.strip_suffix('s') {
        let value: u64 = secs
            .trim()
            .parse()
            .map_err(|_| RuntimeError::InvalidDuration(input.to_string()))?;
        return Ok(Duration::from_secs(value));
    }
    Err(RuntimeError::InvalidDuration(input.to_string()))
}
