use super::model::{PathPattern, Segment};
use crate::SEP;
use crate::rbac::path::{non_empty, strip_slash};
use Segment::{Literal, Param, Rest};
use std::str::FromStr;
use thiserror::Error;

const REST: &str = "**";
const PARAM_OPEN: char = '{';
const PARAM_CLOSE: char = '}';
const LOW: char = '_';
const RESERVED: [char; 3] = [PARAM_OPEN, PARAM_CLOSE, '*'];

/// Ошибки разбора шаблонов путей и HTTP-методов.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PatternError {
    #[error("invalid pattern {pattern:?}: {reason}")]
    InvalidPath { pattern: String, reason: String },

    #[error("invalid method {method:?}: {reason}")]
    InvalidMethod { method: String, reason: String },
}

impl PatternError {
    fn invalid_path(pattern: &str, reason: impl Into<String>) -> Self {
        Self::InvalidPath {
            pattern: pattern.to_string(),
            reason: reason.into(),
        }
    }
}

impl PathPattern {
    pub fn parse(path: &str) -> Result<PathPattern, PatternError> {
        let original = path;
        let path =
            strip_slash(path).map_err(|reason| PatternError::invalid_path(original, reason))?;
        let segments =
            Self::split(path).map_err(|reason| PatternError::invalid_path(original, reason))?;

        if let Some((_, init)) = segments.split_last()
            && init.iter().any(|seg| matches!(seg, Rest))
        {
            return Err(PatternError::invalid_path(
                original,
                "** must be the last segment",
            ));
        }

        Ok(PathPattern { segments })
    }
    pub fn matches(&self, path: &str) -> bool {
        let Some(rest) = path.strip_prefix(SEP) else {
            return false;
        };

        if rest.is_empty() {
            return matches!(self.segments.first(), None | Some(Rest));
        }

        let mut parts = rest.split(SEP);
        for seg in &self.segments {
            match (seg, parts.next()) {
                (Rest, _) => return true,
                (Literal(l), Some(p)) if p == l.as_str() => {}
                (Param, Some(p)) if !p.is_empty() => {}
                _ => return false,
            }
        }
        parts.next().is_none()
    }

    fn split(path: &str) -> Result<Vec<Segment>, String> {
        if path.is_empty() {
            return Ok(vec![]);
        }
        path.split(SEP)
            .map(non_empty)
            .map(|r| r.and_then(|seg| seg.parse::<Segment>()))
            .collect::<Result<Vec<Segment>, String>>()
    }
}

impl FromStr for Segment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == REST {
            return Ok(Rest);
        }
        if let Some(name) = s
            .strip_prefix(PARAM_OPEN)
            .and_then(|r| r.strip_suffix(PARAM_CLOSE))
        {
            if !is_valid_name(name) {
                return Err(format!("invalid param name: {name:?}"));
            }
            return Ok(Param);
        }
        if s.contains(RESERVED) {
            return Err(format!("reserved characters in segment {s:?}"));
        }
        Ok(Literal(s.to_string()))
    }
}

fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == LOW => {
            chars.all(|c| c.is_ascii_alphanumeric() || c == LOW)
        }
        _ => false, // пустая строка или плохой первый символ
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(s: &str) -> PathPattern {
        PathPattern::parse(s).unwrap_or_else(|e| panic!("expected Ok for {s:?}, got Err: {e}"))
    }

    fn parse_err(s: &str) -> String {
        match PathPattern::parse(s) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected Err for {s:?}"),
        }
    }

    // ---------- is_valid_name ----------

    #[test]
    fn valid_names() {
        for n in ["id", "_x", "user_id", "a1", "A_b2"] {
            assert!(is_valid_name(n), "{n:?} должно быть валидно");
        }
    }

    #[test]
    fn invalid_names() {
        for n in ["", "1a", "a-b", "a b", "ы", "a.b"] {
            assert!(!is_valid_name(n), "{n:?} должно быть невалидно");
        }
    }

    // ---------- Segment::from_str ----------

    #[test]
    fn segment_rest() {
        assert!(matches!("**".parse::<Segment>(), Ok(Rest)));
    }

    #[test]
    fn segment_param() {
        assert!(matches!("{id}".parse::<Segment>(), Ok(Param)));
    }

    #[test]
    fn segment_literal() {
        assert!(matches!("users".parse::<Segment>(), Ok(Literal(s)) if s == "users"));
    }

    #[test]
    fn segment_rejects_reserved_chars() {
        for s in ["*", "a*", "a{id}", "{id", "id}", "{{id}}", "***"] {
            assert!(s.parse::<Segment>().is_err(), "{s:?} должно быть ошибкой");
        }
    }

    #[test]
    fn segment_rejects_bad_param_names() {
        for s in ["{}", "{1a}", "{a-b}", "{a b}"] {
            assert!(s.parse::<Segment>().is_err(), "{s:?} должно быть ошибкой");
        }
    }

    // ---------- PathPattern::parse ----------

    #[test]
    fn parse_valid_patterns() {
        for p in [
            "/",
            "/a",
            "/a/b",
            "/users/{id}",
            "/users/{id}/orders",
            "/**",
            "/a/**",
        ] {
            assert!(PathPattern::parse(p).is_ok(), "{p:?} должно парситься");
        }
    }

    #[test]
    fn parse_requires_leading_slash() {
        let e = parse_err("a/b");
        assert!(e.contains("must start with '/'"), "got: {e}");
        assert!(e.contains("\"a/b\""), "ошибка должна содержать шаблон: {e}");
    }

    #[test]
    fn parse_rejects_empty_segments() {
        for p in ["/a/", "/a//b", "//"] {
            assert!(PathPattern::parse(p).is_err(), "{p:?} должно быть ошибкой");
        }
    }

    #[test]
    fn parse_rest_must_be_last() {
        let e = parse_err("/a/**/b");
        assert!(e.contains("last segment"), "got: {e}");
        assert!(PathPattern::parse("/**/**").is_err());
        assert!(PathPattern::parse("/a/**").is_ok());
    }

    #[test]
    fn parse_error_contains_whole_pattern() {
        let e = parse_err("/users/{}");
        assert!(e.contains("\"/users/{}\""), "got: {e}");
    }

    // ---------- PathPattern::matches ----------

    #[test]
    fn matches_root() {
        let p = pat("/");
        assert!(p.matches("/"));
        assert!(!p.matches("/a"));
        assert!(!p.matches(""));
    }

    #[test]
    fn matches_literals() {
        let p = pat("/a/b");
        assert!(p.matches("/a/b"));
        assert!(!p.matches("/a/x")); // регрессия: return true внутри цикла
        assert!(!p.matches("/x/b"));
        assert!(!p.matches("/a"));
        assert!(!p.matches("/a/b/c"));
        assert!(!p.matches("/A/b")); // регистр важен
    }

    #[test]
    fn matches_requires_leading_slash() {
        let p = pat("/a");
        assert!(!p.matches("a"));
        assert!(!p.matches(""));
    }

    #[test]
    fn matches_param() {
        let p = pat("/users/{id}");
        assert!(p.matches("/users/42"));
        assert!(p.matches("/users/abc-def"));
        assert!(!p.matches("/users/")); // пустой параметр
        assert!(!p.matches("/users")); // нет сегмента
        assert!(!p.matches("/users/42/x")); // лишний сегмент
        assert!(!p.matches("/users/42/")); // хвостовой слэш
        assert!(!p.matches("/orders/42"));
    }

    #[test]
    fn matches_param_in_the_middle() {
        let p = pat("/users/{id}/orders");
        assert!(p.matches("/users/7/orders"));
        assert!(!p.matches("/users/7/items"));
        assert!(!p.matches("/users//orders"));
    }

    #[test]
    fn matches_multiple_params() {
        let p = pat("/a/{x}/{y}");
        assert!(p.matches("/a/1/2"));
        assert!(!p.matches("/a/1"));
        assert!(!p.matches("/a/1/"));
    }

    #[test]
    fn matches_rest() {
        let p = pat("/api/**");
        assert!(p.matches("/api/users"));
        assert!(p.matches("/api/users/42/orders"));
        assert!(p.matches("/api/users/42/")); // ** берёт и пустые хвосты
        assert!(!p.matches("/other/users"));
        assert!(!p.matches("/ap/users"));
    }

    #[test]
    fn matches_rest_alone_matches_everything_with_slash() {
        let p = pat("/**");
        assert!(p.matches("/"));
        assert!(p.matches("/a/b/c"));
        assert!(!p.matches("a/b"));
    }

    /// Фиксирует ТЕКУЩЕЕ поведение: `**` совпадает и с нулём сегментов.
    /// Если решишь, что нужен минимум один сегмент, этот тест надо поменять.
    #[test]
    fn rest_matches_zero_segments_current_behavior() {
        assert!(pat("/api/**").matches("/api"));
    }
}
