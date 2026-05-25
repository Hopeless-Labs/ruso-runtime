//! Shared utility helpers with no domain dependencies.

/// Truncate `input` to at most `max_len` bytes, snapping back to the nearest
/// UTF-8 character boundary so multi-byte sequences are never split.
///
/// When the input is longer than `max_len`, an ellipsis `…` is appended.
pub fn truncate_str(input: &str, max_len: usize) -> String {
    if input.len() <= max_len {
        return input.to_string();
    }
    let mut end = max_len;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &input[..end])
}

#[cfg(test)]
mod tests {
    use super::truncate_str;

    #[test]
    fn short_input_unchanged() {
        assert_eq!(truncate_str("hi", 10), "hi");
    }

    #[test]
    fn ascii_truncates_with_ellipsis() {
        let out = truncate_str("abcdefghij", 5);
        assert_eq!(out, "abcde…");
    }

    #[test]
    fn does_not_panic_on_multibyte_boundary() {
        // "日本語" is 9 UTF-8 bytes (3 chars × 3 bytes). max_len=4 falls
        // mid-character; the unfixed implementation would panic.
        let out = truncate_str("日本語テキスト", 4);
        // We snap back to char boundary 3 (after first char), giving "日…".
        assert_eq!(out, "日…");
    }

    #[test]
    fn handles_emoji() {
        // 🦀 is 4 bytes. max_len=2 falls mid-char.
        let out = truncate_str("🦀🦀🦀", 2);
        assert_eq!(out, "…");
    }

    #[test]
    fn zero_max_len_returns_just_ellipsis() {
        assert_eq!(truncate_str("hello", 0), "…");
    }
}
