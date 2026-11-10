//! PDF name `#xx` encoding, the classic way to hide `/JavaScript` from naive scanners.

/// `/Name` with every character written as `#xx`: `JS` → `/#4A#53`.
pub fn name_encoded_all(name: &str) -> String {
    let idx: Vec<usize> = (0..name.len()).collect();
    name_encoded(name, &idx)
}

/// `/Name` with the bytes at `indices` written as `#xx`: `("JS", &[1])` → `/J#53`.
pub fn name_encoded(name: &str, indices: &[usize]) -> String {
    let mut out = String::from("/");
    for (i, b) in name.bytes().enumerate() {
        if indices.contains(&i) {
            out.push_str(&format!("#{b:02X}"));
        } else {
            out.push(char::from(b));
        }
    }
    out
}

fn is_name_end(b: u8) -> bool {
    b.is_ascii_whitespace() || b"()<>[]{}/%".contains(&b)
}

/// Rewrites every whole-token occurrence of `/N` (for `N` in `names`) in PDF
/// source text to its fully encoded form. `/JSX` is untouched when `JS` is listed.
pub fn encode_names_in(text: &str, names: &[&str]) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len() * 2);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && !is_name_end(bytes[end]) {
                end += 1;
            }
            let token = &text[start..end];
            if names.contains(&token) {
                out.push_str(&name_encoded_all(token));
            } else {
                out.push('/');
                out.push_str(token);
            }
            i = end;
        } else {
            let ch = text[i..].chars().next().unwrap_or('\u{FFFD}');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_selected_or_all_chars() {
        assert_eq!(name_encoded("JS", &[1]), "/J#53");
        assert_eq!(name_encoded_all("JS"), "/#4A#53");
        assert_eq!(name_encoded("Launch", &[]), "/Launch");
    }

    #[test]
    fn rewrites_whole_tokens_only() {
        let src = "<< /S /JavaScript /JS (x) /JSX 1 /Type/JS>>";
        let out = encode_names_in(src, &["JS", "JavaScript"]);
        assert_eq!(
            out,
            format!(
                "<< /S {} {} (x) /JSX 1 /Type{}>>",
                name_encoded_all("JavaScript"),
                name_encoded_all("JS"),
                name_encoded_all("JS")
            )
        );
    }

    #[test]
    fn leaves_other_text_alone() {
        let src = "(https://example.invalid/quelda-test) /URI";
        assert_eq!(
            encode_names_in(src, &["S"]),
            "(https://example.invalid/quelda-test) /URI"
        );
    }
}
