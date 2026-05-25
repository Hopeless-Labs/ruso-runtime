use crate::runtime::error::RuntimeError;

/// Decode a contiguous hex string (spaces allowed) into raw bytes.
pub fn decode_hex(input: &str) -> Result<Vec<u8>, RuntimeError> {
    let hex: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    if !hex.len().is_multiple_of(2) || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(RuntimeError::Other(format!(
            "invalid hex body: expected pairs of hex digits, got {hex:?}"
        )));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| RuntimeError::Other(format!("invalid hex body: {err}")))
}
