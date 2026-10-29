use crate::SEP;

const DOT: &str = ".";
const DOUBLE_DOT: &str = "..";
const BACKSLASH: char = '\\';
const PERCENT: char = '%';
const FORBIDDEN: [char; 2] = [BACKSLASH, ';'];

pub fn validate_path(path: &str) -> Result<(), String> {
    check_path(path).map_err(|e| format!("invalid path {path:?}: {e}"))
}

fn check_path(path: &str) -> Result<(), String> {
    let path = strip_slash(path)?;

    if path.is_empty() {
        return Ok(());
    }

    if path.chars().any(|c| FORBIDDEN.contains(&c)) {
        return Err("backslash and ';' are not allowed".to_string());
    }

    if path.chars().any(char::is_control) {
        return Err("control characters are not allowed".to_string());
    }

    if path.contains(PERCENT) {
        return Err("percent-encoded characters are not allowed".to_string());
    }

    for seg in path.split(SEP) {
        non_empty(seg)?;
        validate_segment(seg)?;
    }

    Ok(())
}

pub fn strip_slash(path: &str) -> Result<&str, String> {
    path.strip_prefix(SEP)
        .ok_or_else(|| "must start with '/'".to_string())
}

pub fn non_empty(seg: &str) -> Result<&str, String> {
    if seg.is_empty() {
        Err("segment cannot be empty".to_string())
    } else {
        Ok(seg)
    }
}

fn validate_segment(seg: &str) -> Result<(), String> {
    if seg == DOT || seg == DOUBLE_DOT {
        return Err("'.' and '..' are not allowed".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_valid_paths() {
        let paths = [
            "/",
            "/api",
            "/api/users",
            "/api/users/123",
            "/file.txt",
            "/v1.0",
            "/...",
            "/....",
            "/пользователи",
            "/files/report.pdf",
            "/v1.2/x",
            "/.well-known/jwks.json",
        ];

        for path in paths {
            assert!(
                validate_path(path).is_ok(),
                "path should be valid: {path:?}"
            );
        }
    }

    #[test]
    fn validate_path_must_start_with_slash() {
        let paths = ["", "api", "api/users", "a/b"];

        for path in paths {
            assert!(
                validate_path(path).is_err(),
                "path should be invalid: {path:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_empty_segments() {
        let paths = ["//", "/a//b", "/a/", "/a//", "///a"];

        for path in paths {
            assert!(
                validate_path(path).is_err(),
                "path should be invalid: {path:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_dot_segments() {
        let paths = ["/.", "/..", "/a/./b", "/a/../b", "/a/.."];

        for path in paths {
            assert!(
                validate_path(path).is_err(),
                "path should be invalid: {path:?}"
            );
        }
    }

    #[test]
    fn validate_allows_multiple_dots_inside_segment() {
        let paths = ["/...", "/....", "/a...b", "/file.txt", "/v1.0"];

        for path in paths {
            assert!(
                validate_path(path).is_ok(),
                "path should be valid: {path:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_backslash() {
        let paths = ["/a\\b", "/\\", "/api\\users"];

        for path in paths {
            assert!(
                validate_path(path).is_err(),
                "path should be invalid: {path:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_control_characters() {
        let paths = ["/a\0b", "/a\nb", "/a\rb", "/a\tb"];

        for path in paths {
            assert!(
                validate_path(path).is_err(),
                "path should be invalid: {path:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_any_percent_encoding() {
        let paths = [
            "/%2e",
            "/%2E",
            "/%2e%2e/b",
            "/a/%2E%2E/b",
            "/a%2fb",
            "/a%2Fb",
            "/a%5cb",
            "/a%5Cb",
            "/a/%2f/b",
            "/a/%5c/b",
            "/%61pi/users",
            "/a%20b",
            "/%41",
            "/a%3bb",
        ];

        for path in paths {
            assert!(
                validate_path(path).is_err(),
                "path should be invalid: {path:?}"
            );
        }
    }

    #[test]
    fn validate_percent_error_message_is_explicit() {
        let error = validate_path("/%61pi").unwrap_err();

        assert!(error.contains("percent-encoded characters are not allowed"));
    }

    #[test]
    fn validate_returns_error_for_missing_leading_slash() {
        let error = validate_path("api/users").unwrap_err();

        assert!(error.contains("must start with '/'"));
    }

    #[test]
    fn validate_returns_error_for_empty_segment() {
        let error = validate_path("/a//b").unwrap_err();

        assert!(error.contains("segment cannot be empty"));
    }

    #[test]
    fn validate_returns_error_for_dot_segment() {
        let error = validate_path("/a/../b").unwrap_err();

        assert!(error.contains("'.' and '..' are not allowed"));
    }

    #[test]
    fn validate_returns_error_for_backslash() {
        let error = validate_path("/a\\b").unwrap_err();

        assert!(error.contains("backslash") && error.contains("not allowed"));
    }

    #[test]
    fn validate_returns_error_for_control_character() {
        let error = validate_path("/a\nb").unwrap_err();

        assert!(error.contains("control characters are not allowed"));
    }

    #[test]
    fn validate_returns_error_for_encoded_sequence() {
        let error = validate_path("/a%2Fb").unwrap_err();

        assert!(error.contains("encoded"));
    }
}
