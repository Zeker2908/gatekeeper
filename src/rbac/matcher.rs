use super::model::{Endpoint, MethodMatch, PathPattern, RuleSet};
use super::pattern::PatternError;
use http::Method;
use std::str::FromStr;

const ANY: &str = "*";

impl MethodMatch {
    pub fn matches(&self, m: &Method) -> bool {
        match self {
            MethodMatch::Any => true,
            MethodMatch::Exact(expected) => expected == m,
        }
    }
}

impl Endpoint {
    pub fn new(method: &str, path: &str) -> Result<Self, PatternError> {
        Ok(Endpoint {
            method: method.parse()?,
            pattern: PathPattern::parse(path)?,
        })
    }
    pub fn matches(&self, method: &Method, path: &str) -> bool {
        self.method.matches(method) && self.pattern.matches(path)
    }
}

impl RuleSet {
    pub fn is_allowed(&self, roles: &[String], method: &Method, path: &str) -> bool {
        roles
            .iter()
            .filter_map(|r| self.roles.get(r))
            .flatten()
            .any(|endpoint| endpoint.matches(method, path))
    }
    pub fn is_public(&self, method: &Method, path: &str) -> bool {
        self.public.iter().any(|e| e.matches(method, path))
    }
}

impl FromStr for MethodMatch {
    type Err = PatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == ANY {
            return Ok(MethodMatch::Any);
        }
        s.to_ascii_uppercase()
            .parse::<Method>()
            .map(MethodMatch::Exact)
            .map_err(|e| PatternError::InvalidMethod {
                method: s.to_string(),
                reason: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ---------- хелперы ----------

    fn ep(method: &str, path: &str) -> Endpoint {
        Endpoint::new(method, path)
            .unwrap_or_else(|e| panic!("expected Ok for {method} {path}, got Err: {e}"))
    }

    fn rules(spec: &[(&str, &[(&str, &str)])]) -> RuleSet {
        let mut roles: HashMap<String, Vec<Endpoint>> = HashMap::new();

        for (role, eps) in spec {
            roles.insert(
                role.to_string(),
                eps.iter().map(|(m, p)| ep(m, p)).collect(),
            );
        }

        RuleSet {
            roles,
            public: vec![],
        }
    }

    fn roles(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    // ---------- MethodMatch::from_str ----------

    #[test]
    fn method_match_star_is_any() {
        assert_eq!("*".parse::<MethodMatch>(), Ok(MethodMatch::Any));
    }

    #[test]
    fn method_match_exact_is_case_insensitive() {
        for s in ["GET", "get", "Get", "gEt"] {
            assert_eq!(
                s.parse::<MethodMatch>(),
                Ok(MethodMatch::Exact(Method::GET)),
                "{s:?}"
            );
        }
        assert_eq!(
            "post".parse::<MethodMatch>(),
            Ok(MethodMatch::Exact(Method::POST))
        );
    }

    #[test]
    fn method_match_extension_method_is_accepted() {
        // parse::<Method> принимает любой валидный токен, не только стандартные методы
        let expected = Method::from_bytes(b"PURGE").unwrap();
        assert_eq!(
            "purge".parse::<MethodMatch>(),
            Ok(MethodMatch::Exact(expected))
        );
    }

    #[test]
    fn method_match_rejects_invalid_tokens() {
        for s in ["", "G E T", "GET\n", "GÉT", "GET/POST"] {
            assert!(
                s.parse::<MethodMatch>().is_err(),
                "{s:?} должно быть ошибкой"
            );
        }
    }

    #[test]
    fn method_match_error_contains_input() {
        let e = "G E T".parse::<MethodMatch>().unwrap_err().to_string();
        assert!(e.contains("\"G E T\""), "got: {e}");
    }

    // ---------- MethodMatch::matches ----------

    #[test]
    fn any_matches_every_method() {
        let m = MethodMatch::Any;
        assert!(m.matches(&Method::GET));
        assert!(m.matches(&Method::DELETE));
        assert!(m.matches(&Method::from_bytes(b"PURGE").unwrap()));
    }

    #[test]
    fn exact_matches_only_itself() {
        let m = MethodMatch::Exact(Method::GET);
        assert!(m.matches(&Method::GET));
        assert!(!m.matches(&Method::POST));
        assert!(!m.matches(&Method::HEAD)); // HEAD не считается GET
    }

    // ---------- Endpoint::new ----------

    #[test]
    fn endpoint_new_valid() {
        assert!(Endpoint::new("GET", "/users/{id}").is_ok());
        assert!(Endpoint::new("*", "/**").is_ok());
        assert!(Endpoint::new("delete", "/").is_ok());
    }

    #[test]
    fn endpoint_new_rejects_bad_method() {
        assert!(Endpoint::new("G E T", "/a").is_err());
        assert!(Endpoint::new("", "/a").is_err());
    }

    #[test]
    fn endpoint_new_rejects_bad_path() {
        assert!(Endpoint::new("GET", "a").is_err()); // нет '/'
        assert!(Endpoint::new("GET", "/a//b").is_err()); // пустой сегмент
        assert!(Endpoint::new("GET", "/a/**/b").is_err()); // ** не в конце
        assert!(Endpoint::new("GET", "/a/{}").is_err()); // пустое имя параметра
    }

    // ---------- Endpoint::matches ----------

    #[test]
    fn endpoint_any_method_with_path() {
        let e = ep("*", "/a");
        assert!(e.matches(&Method::GET, "/a"));
        assert!(e.matches(&Method::DELETE, "/a"));
        assert!(!e.matches(&Method::GET, "/b"));
    }

    #[test]
    fn endpoint_requires_both_method_and_path() {
        let e = ep("GET", "/users/{id}");
        assert!(e.matches(&Method::GET, "/users/42"));
        assert!(!e.matches(&Method::POST, "/users/42")); // метод не тот
        assert!(!e.matches(&Method::GET, "/orders/42")); // путь не тот
        assert!(!e.matches(&Method::POST, "/orders/42")); // оба не те
    }

    #[test]
    fn endpoint_rule_method_normalized_once() {
        let e = ep("get", "/a"); // в правиле регистр не важен
        assert!(e.matches(&Method::GET, "/a"));
    }

    // ---------- RuleSet::is_allowed ----------

    #[test]
    fn allowed_by_matching_rule() {
        let r = rules(&[("user", &[("GET", "/users/{id}")])]);
        assert!(r.is_allowed(&roles(&["user"]), &Method::GET, "/users/42"));
    }

    #[test]
    fn denied_when_method_or_path_differs() {
        let r = rules(&[("user", &[("GET", "/users/{id}")])]);
        let u = roles(&["user"]);
        assert!(!r.is_allowed(&u, &Method::DELETE, "/users/42"));
        assert!(!r.is_allowed(&u, &Method::GET, "/users"));
        assert!(!r.is_allowed(&u, &Method::GET, "/users/42/orders"));
        assert!(!r.is_allowed(&u, &Method::GET, "/admin"));
    }

    #[test]
    fn denied_by_default_without_roles() {
        let r = rules(&[("admin", &[("*", "/**")])]);
        assert!(!r.is_allowed(&[], &Method::GET, "/anything"));
    }

    #[test]
    fn denied_for_unknown_role() {
        let r = rules(&[("admin", &[("*", "/**")])]);
        assert!(!r.is_allowed(&roles(&["ghost"]), &Method::GET, "/"));
    }

    #[test]
    fn role_names_are_case_sensitive() {
        // фиксирует текущее поведение: "Admin" и "admin" это разные ключи
        let r = rules(&[("admin", &[("*", "/**")])]);
        assert!(!r.is_allowed(&roles(&["Admin"]), &Method::GET, "/"));
    }

    #[test]
    fn admin_wildcard_allows_everything() {
        let r = rules(&[("admin", &[("*", "/**")])]);
        let a = roles(&["admin"]);
        assert!(r.is_allowed(&a, &Method::DELETE, "/any/path/here"));
        assert!(r.is_allowed(&a, &Method::GET, "/"));
    }

    #[test]
    fn rights_are_union_of_roles() {
        let r = rules(&[
            ("reader", &[("GET", "/docs/**")]),
            ("writer", &[("POST", "/docs/{id}")]),
        ]);
        let both = roles(&["reader", "writer"]);
        assert!(r.is_allowed(&both, &Method::GET, "/docs/a/b"));
        assert!(r.is_allowed(&both, &Method::POST, "/docs/7"));
        assert!(!r.is_allowed(&both, &Method::DELETE, "/docs/7"));

        // по одной роли права не расширяются
        assert!(!r.is_allowed(&roles(&["reader"]), &Method::POST, "/docs/7"));
    }

    #[test]
    fn unknown_role_does_not_block_known_one() {
        let r = rules(&[("user", &[("GET", "/me")])]);
        assert!(r.is_allowed(&roles(&["ghost", "user"]), &Method::GET, "/me"));
    }

    #[test]
    fn role_with_empty_rule_list_allows_nothing() {
        let r = rules(&[("empty", &[])]);
        assert!(!r.is_allowed(&roles(&["empty"]), &Method::GET, "/"));
    }

    #[test]
    fn user_cannot_reach_admin_paths() {
        let r = rules(&[
            ("user", &[("GET", "/users/{id}")]),
            ("admin", &[("*", "/admin/**")]),
        ]);
        let u = roles(&["user"]);
        assert!(!r.is_allowed(&u, &Method::GET, "/admin/users"));
        assert!(!r.is_allowed(&u, &Method::DELETE, "/admin/users/1"));
    }
}
