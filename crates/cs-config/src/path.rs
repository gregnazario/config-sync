//! Pure path resolution: expands `~`, `$VAR` (Unix), and `%VAR%` (Windows).
//! No filesystem access — fully unit-testable on any platform.

use crate::error::ConfigError;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Mac,
    Windows,
    Linux,
    FreeBSD,
}

impl Platform {
    fn is_unix(&self) -> bool {
        matches!(self, Platform::Mac | Platform::Linux | Platform::FreeBSD)
    }
}

/// Resolve a raw config path against the given platform and home directory.
///
/// Rules (per the design spec):
/// - `~` is expanded to `home` on every platform.
/// - On Unix, `$VAR` and `${VAR}` are expanded from the process environment.
/// - On Windows, `%VAR%` is expanded from the process environment.
/// - On Unix, `%VAR%` is left literal; on Windows, `$VAR` is left literal.
pub fn resolve(raw: &str, platform: Platform, home: &str) -> Result<PathBuf, ConfigError> {
    let mut s = raw.to_string();
    if s.starts_with('~') {
        s = format!("{home}{}", &s[1..]);
    }
    if platform.is_unix() {
        s = expand_unix_vars(&s);
    } else {
        s = expand_win_vars(&s);
    }
    Ok(PathBuf::from(s))
}

fn expand_unix_vars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            // ${VAR} form
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                if let Some(end) = bytes[i + 2..].iter().position(|&b| b == b'}') {
                    let name = std::str::from_utf8(&bytes[i + 2..i + 2 + end]).unwrap_or("");
                    if let Ok(val) = std::env::var(name) {
                        out.push_str(&val);
                    }
                    i = i + 2 + end + 1;
                    continue;
                }
            }
            // $VAR form
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            if j > i + 1 {
                let name = std::str::from_utf8(&bytes[i + 1..j]).unwrap_or("");
                if let Ok(val) = std::env::var(name) {
                    out.push_str(&val);
                }
                i = j;
                continue;
            }
            // Lone '$' with no name following.
            out.push('$');
            i += 1;
        } else {
            // Push the UTF-8 char starting at this byte.
            let ch_len = utf8_char_len(bytes[i]);
            out.push_str(std::str::from_utf8(&bytes[i..i + ch_len]).unwrap_or(""));
            i += ch_len;
        }
    }
    out
}

fn expand_win_vars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let mut name = String::new();
            let mut found_close = false;
            while let Some(&n) = chars.peek() {
                chars.next();
                if n == '%' {
                    found_close = true;
                    break;
                }
                name.push(n);
            }
            if found_close && !name.is_empty() {
                if let Ok(val) = std::env::var(&name) {
                    out.push_str(&val);
                } else {
                    out.push('%');
                    out.push_str(&name);
                    out.push('%');
                }
            } else {
                // Unterminated or empty % — emit literally.
                out.push('%');
                out.push_str(&name);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn utf8_char_len(byte: u8) -> usize {
    if byte < 0x80 {
        1
    } else if byte >> 5 == 0b110 {
        2
    } else if byte >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expands_on_unix() {
        let p = resolve("~/.vimrc", Platform::Linux, "/home/g").unwrap();
        assert_eq!(p, PathBuf::from("/home/g/.vimrc"));
    }

    #[test]
    fn tilde_expands_on_mac() {
        let p = resolve("~/.config/x", Platform::Mac, "/Users/g").unwrap();
        assert_eq!(p, PathBuf::from("/Users/g/.config/x"));
    }

    #[test]
    fn unix_env_var_expands_on_unix() {
        std::env::set_var("CSYNC_TEST_VAR", "/opt/x");
        let p = resolve("$CSYNC_TEST_VAR/y", Platform::Linux, "/home/g").unwrap();
        assert_eq!(p, PathBuf::from("/opt/x/y"));
    }

    #[test]
    fn unix_env_brace_form_expands_on_unix() {
        std::env::set_var("CSYNC_TEST_VAR", "/opt/x");
        let p = resolve("${CSYNC_TEST_VAR}/y", Platform::Linux, "/home/g").unwrap();
        assert_eq!(p, PathBuf::from("/opt/x/y"));
    }

    #[test]
    fn unix_var_not_expanded_on_windows() {
        let p = resolve("$HOME/x", Platform::Windows, r"C:\Users\g").unwrap();
        assert_eq!(p, PathBuf::from(r"$HOME/x"));
    }

    #[test]
    fn windows_var_not_expanded_on_unix() {
        let p = resolve("%APPDATA%/vim", Platform::Linux, "/home/g").unwrap();
        assert_eq!(p, PathBuf::from("%APPDATA%/vim"));
    }

    #[test]
    fn windows_var_expands_on_windows() {
        std::env::set_var("CSYNC_WIN_VAR", r"C:\Data");
        let p = resolve("%CSYNC_WIN_VAR%/file", Platform::Windows, r"C:\Users\g").unwrap();
        // The expanded value is spliced in; the trailing "/file" is preserved
        // as-is (forward slashes are valid on Windows and path normalization is
        // the OS's job at use time).
        assert_eq!(p, PathBuf::from("C:\\Data/file"));
    }

    #[test]
    fn unterminated_windows_var_emitted_literally() {
        let p = resolve("%APPDATA/file", Platform::Windows, r"C:\Users\g").unwrap();
        assert_eq!(p, PathBuf::from(r"%APPDATA/file"));
    }

    #[test]
    fn lone_dollar_emitted_literally_on_unix() {
        let p = resolve("$", Platform::Linux, "/home/g").unwrap();
        assert_eq!(p, PathBuf::from("$"));
    }

    #[test]
    fn no_substitutions_passes_through() {
        let p = resolve("/etc/static.conf", Platform::FreeBSD, "/home/g").unwrap();
        assert_eq!(p, PathBuf::from("/etc/static.conf"));
    }
}
