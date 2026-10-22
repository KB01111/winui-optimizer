//! Small, pure helpers shared across the crate. Everything here is fully
//! unit-tested and free of platform calls.

/// Trim whitespace and return `None` when nothing is left.
pub(crate) fn clean_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Remove a leading UTF-8 byte order mark (PowerShell occasionally emits one
/// when output is redirected).
pub(crate) fn strip_bom(value: &str) -> &str {
    value.trim_start_matches('\u{feff}')
}

/// Truncate to at most `max_chars` characters, never splitting a UTF-8 code
/// point.
pub(crate) fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_string_trims_and_filters_empty() {
        assert_eq!(clean_string("  hello  "), Some("hello".to_string()));
        assert_eq!(clean_string(""), None);
        assert_eq!(clean_string("   \t\r\n"), None);
    }

    #[test]
    fn strip_bom_only_removes_leading_bom() {
        assert_eq!(strip_bom("\u{feff}{\"a\":1}"), "{\"a\":1}");
        assert_eq!(strip_bom("{\"a\":1}"), "{\"a\":1}");
        assert_eq!(strip_bom("\u{feff}\u{feff}x"), "x");
        assert_eq!(strip_bom("x\u{feff}"), "x\u{feff}");
    }

    #[test]
    fn truncate_chars_respects_char_boundaries() {
        assert_eq!(truncate_chars("hello", 10), "hello");
        assert_eq!(truncate_chars("hello", 3), "hel");
        assert_eq!(truncate_chars("hello", 0), "");
        assert_eq!(truncate_chars("åäö", 2), "åä");
        assert_eq!(truncate_chars("用户数据", 2), "用户");
    }
}
