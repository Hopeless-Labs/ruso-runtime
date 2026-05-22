pub fn truncate_str(input: &str, max_len: usize) -> String {
    if input.len() <= max_len {
        return input.to_string();
    }
    format!("{}…", &input[..max_len])
}
