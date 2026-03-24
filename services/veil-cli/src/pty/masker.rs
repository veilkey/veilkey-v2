use crate::api::VeilKeyClient;
use crate::config::CompiledPattern;

const BOLD: &str = "\x1b[1m";
const CYAN: &str = "\x1b[36m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[92m";
const RESET: &str = "\x1b[0m";

pub fn colorize_ref(vk_ref: &str) -> String {
    if vk_ref.contains(":LOCAL:") {
        format!("{}{}{}{}", BOLD, CYAN, vk_ref, RESET)
    } else if vk_ref.contains(":TEMP:") {
        format!("{}{}{}{}", BOLD, RED, vk_ref, RESET)
    } else {
        vk_ref.to_string()
    }
}

/// VE: colorize original value in green — same text, different color.
pub fn colorize_ve_ref(original: &str, _ve_ref: &str) -> String {
    format!("{}{}{}", GREEN, original, RESET)
}

/// Replace a secret with a colorized VK ref, padded to EXACTLY the original width.
/// This ensures no surrounding text shifts position and no characters leak.
/// If the ref is longer than the original, we truncate the visible ref to fit.
pub fn padded_colorize_ref(vk_ref: &str, original_len: usize) -> String {
    if original_len == 0 {
        return String::new();
    }
    let ref_visible_len = vk_ref.chars().count();
    if ref_visible_len <= original_len {
        // Ref fits — pad with spaces to fill the original width
        let colored = colorize_ref(vk_ref);
        let pad = original_len - ref_visible_len;
        if pad > 0 {
            format!("{}{}", colored, " ".repeat(pad))
        } else {
            colored
        }
    } else {
        // Ref is longer than original — truncate to fit exactly
        let truncated: String = vk_ref.chars().take(original_len).collect();
        colorize_ref(&truncated)
    }
}

/// Mask secrets in PTY output data.
/// - Known secrets from mask_map are replaced with colorized VK refs.
/// - Lines with replacements get ANSI line-clear to overwrite echo-back.
/// - Pattern-detected secrets are auto-registered or redacted (fail-closed).
pub fn mask_output(
    data: &[u8],
    mask_map: &[(String, String)],
    ve_map: &[(String, String)],
    patterns: &[CompiledPattern],
    client: &VeilKeyClient,
    recent_input: &str,
) -> Vec<u8> {
    let mut s = String::from_utf8_lossy(data).to_string();
    let mut had_replacement = false;

    // 1. Known secrets — replace with colorized VK refs
    for (plaintext, vk_ref) in mask_map {
        if !plaintext.is_empty() && s.contains(plaintext.as_str()) {
            s = s.replace(
                plaintext.as_str(),
                &padded_colorize_ref(vk_ref, plaintext.len()),
            );
            had_replacement = true;
        }
    }

    // Line-clear on lines that had secrets replaced (contain our BOLD+CYAN or BOLD+RED).
    // Only match our colorize_ref output, not pre-existing ANSI codes (e.g. colored prompts).
    if had_replacement {
        let mut cleared = String::new();
        for (i, line) in s.split('\n').enumerate() {
            if i > 0 {
                cleared.push('\n');
            }
            let has_our_ansi = line.contains("\x1b[1m\x1b[36m") || line.contains("\x1b[1m\x1b[31m");
            if has_our_ansi {
                cleared.push_str("\r\x1b[2K");
            }
            cleared.push_str(line);
        }
        s = cleared;
    }

    // 2. Pattern-detected secrets — auto-register or redact
    let scan_copy = s.clone();
    for pat in patterns {
        for caps in pat.regex.captures_iter(&scan_copy) {
            let m = caps
                .get(pat.group.max(1))
                .or_else(|| caps.get(1))
                .unwrap_or_else(|| caps.get(0).unwrap());
            let secret = m.as_str().trim_end_matches(['\r', '\n']);
            if secret.len() < 8 || secret.starts_with("VK:") {
                continue;
            }
            if mask_map.iter().any(|(p, _)| p == secret) {
                continue;
            }
            if !recent_input.is_empty() && recent_input.contains(secret) {
                continue;
            }
            match client.issue(secret) {
                Ok(ref_canonical) => {
                    s = s.replace(secret, &padded_colorize_ref(&ref_canonical, secret.len()));
                }
                Err(e) => {
                    eprintln!(
                        "[veilkey] issue failed for pattern {}: {} — redacting (fail-closed)",
                        pat.name, e
                    );
                    let redacted = format!("[REDACTED:{}]", pat.name);
                    s = s.replace(secret, &padded_colorize_ref(&redacted, secret.len()));
                }
            }
        }
    }

    for (plaintext, ve_ref) in ve_map {
        if !plaintext.is_empty() && s.contains(plaintext.as_str()) {
            s = s.replace(plaintext.as_str(), &colorize_ve_ref(plaintext, ve_ref));
        }
    }

    s.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip_ansi(s: &str) -> String {
        let re = regex::Regex::new(r"\x1b\[[0-9;]*m").unwrap();
        re.replace_all(s, "").to_string()
    }

    #[test]
    fn test_padded_ref_exact_width() {
        // Secret "my-password-123" (15 chars) → ref "VK:LOCAL:abcd1234" (17 chars)
        let result = padded_colorize_ref("VK:LOCAL:abcd1234", 15);
        let visible = strip_ansi(&result);
        // Ref is longer than original → should truncate to 15 chars
        assert_eq!(visible.chars().count(), 15, "visible width must match original: got [{}]", visible);
    }

    #[test]
    fn test_padded_ref_shorter_ref() {
        // Secret is 30 chars, ref is 18 chars → 12 spaces padding
        let result = padded_colorize_ref("VK:LOCAL:6da25530", 30);
        let visible = strip_ansi(&result);
        assert_eq!(visible.chars().count(), 30, "visible width must be 30: got [{}]", visible);
        assert!(visible.starts_with("VK:LOCAL:6da25530"), "must start with ref");
        assert!(visible.ends_with("            "), "must end with 12 spaces");
    }

    #[test]
    fn test_padded_ref_equal_length() {
        let result = padded_colorize_ref("VK:LOCAL:6da25530", 18);
        let visible = strip_ansi(&result);
        assert_eq!(visible.chars().count(), 18);
        assert_eq!(visible, "VK:LOCAL:6da25530 ");
        // Wait - "VK:LOCAL:6da25530" is 18 chars, padding = 0
        // Actually let's recount: V-K-:-L-O-C-A-L-:-6-d-a-2-5-5-3-0 = 17 chars
    }

    #[test]
    fn test_replacement_preserves_surrounding_text() {
        let original = "user:secretpassword@host:5432";
        let mask_map = vec![
            ("secretpassword".to_string(), "VK:LOCAL:abc123".to_string()),
        ];
        let mut s = original.to_string();
        for (plaintext, vk_ref) in &mask_map {
            if s.contains(plaintext.as_str()) {
                s = s.replace(plaintext.as_str(), &padded_colorize_ref(vk_ref, plaintext.len()));
            }
        }
        let visible = strip_ansi(&s);
        // "secretpassword" = 14 chars, "VK:LOCAL:abc123" = 15 chars → truncated to 14
        assert_eq!(visible.len(), original.len(), "total width must be preserved: got [{}]", visible);
        assert!(visible.contains("@host:5432"), "surrounding text must be intact");
        assert!(!visible.contains("secret"), "secret must not leak");
    }

    #[test]
    fn test_no_leak_when_ref_longer_than_secret() {
        // Short password "pass" (4 chars) replaced by "VK:LOCAL:6da25530" (17 chars)
        // Old code: ref just replaces, line gets 13 chars longer → surrounding text shifts
        // New code: ref truncated to 4 chars → "VK:L"
        let result = padded_colorize_ref("VK:LOCAL:6da25530", 4);
        let visible = strip_ansi(&result);
        assert_eq!(visible.chars().count(), 4, "must fit in 4 chars: got [{}]", visible);
    }
}

