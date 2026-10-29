use crate::http_client::HttpClient;
use crate::rbac::model::{Endpoint, RuleSet, RulesError};
use serde::Deserialize;
use std::collections::HashMap;
use thiserror::Error;

/// Ошибки загрузки и разбора правил из внешнего источника.
#[derive(Debug, Error)]
pub enum RulesSourceError {
    #[error("{0}")]
    Http(String),

    #[error("invalid rules JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("invalid rules content: {0}")]
    InvalidRules(#[from] RulesError),

    #[error("rules source returned no rules")]
    Empty,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesDto {
    #[serde(default)]
    pub public: Vec<EndpointDto>,
    pub rules: HashMap<String, Vec<EndpointDto>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointDto {
    pub method: String,
    pub path: String,
}

impl TryFrom<RulesDto> for RuleSet {
    type Error = RulesError;

    fn try_from(dto: RulesDto) -> Result<Self, Self::Error> {
        let mut roles = HashMap::with_capacity(dto.rules.len());

        for (role, endpoints) in dto.rules {
            if role.trim().is_empty() {
                return Err(RulesError::EmptyRole { role });
            }

            if endpoints.is_empty() {
                continue;
            }

            let mut parsed = Vec::with_capacity(endpoints.len());

            for (index, ep) in endpoints.into_iter().enumerate() {
                parsed.push(
                    Endpoint::new(&ep.method, &ep.path).map_err(|source| {
                        RulesError::InvalidRule {
                            role: role.clone(),
                            index,
                            source,
                        }
                    })?,
                );
            }

            roles.insert(role, parsed);
        }

        let public = dto
            .public
            .into_iter()
            .enumerate()
            .map(|(index, ep)| {
                Endpoint::new(&ep.method, &ep.path)
                    .map_err(|source| RulesError::InvalidPublicRule { index, source })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(RuleSet { roles, public })
    }
}

pub trait RulesSource: Send + Sync {
    fn load(&self) -> impl Future<Output = Result<RuleSet, RulesSourceError>> + Send;
}

pub struct HttpRulesSource {
    http: HttpClient,
    url: String,
}

impl HttpRulesSource {
    pub fn new(http: HttpClient, url: String) -> Self {
        Self { http, url }
    }
}

impl RulesSource for HttpRulesSource {
    async fn load(&self) -> Result<RuleSet, RulesSourceError> {
        let body = self
            .http
            .get_text("rules source", &self.url)
            .await
            .map_err(RulesSourceError::Http)?;

        parse_rules(&body)
    }
}

fn parse_rules(body: &str) -> Result<RuleSet, RulesSourceError> {
    let dto = serde_json::from_str::<RulesDto>(body)?;

    let rules = RuleSet::try_from(dto)?;

    if rules.roles.is_empty() {
        return Err(RulesSourceError::Empty);
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use serde_json::from_str;

    // ---------- хелперы ----------

    fn ep(method: &str, path: &str) -> EndpointDto {
        EndpointDto {
            method: method.into(),
            path: path.into(),
        }
    }

    fn dto(public: Vec<EndpointDto>, rules: Vec<(&str, Vec<EndpointDto>)>) -> RulesDto {
        RulesDto {
            public,
            rules: rules
                .into_iter()
                .map(|(role, eps)| (role.to_string(), eps))
                .collect(),
        }
    }

    /// Достаёт текст ошибки, не требуя `Debug`/`PartialEq` у значения
    fn err_of<T, E: std::fmt::Display>(r: Result<T, E>) -> String {
        match r {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    // ---------- RuleSet::try_from: роли ----------

    #[test]
    fn should_group_rules_by_role() {
        let d = dto(
            vec![],
            vec![
                ("admin", vec![ep("GET", "/users"), ep("DELETE", "/users")]),
                ("user", vec![ep("POST", "/orders")]),
            ],
        );

        let result = RuleSet::try_from(d).unwrap();

        assert_eq!(result.roles.len(), 2);
        assert_eq!(result.roles["admin"].len(), 2);
        assert_eq!(result.roles["user"].len(), 1);
    }

    #[test]
    fn should_keep_rule_order_within_role() {
        let d = dto(
            vec![],
            vec![("admin", vec![ep("GET", "/a"), ep("GET", "/b")])],
        );

        let result = RuleSet::try_from(d).unwrap();
        let admin = &result.roles["admin"];

        assert!(admin[0].matches(&Method::GET, "/a"));
        assert!(!admin[0].matches(&Method::GET, "/b"));
        assert!(admin[1].matches(&Method::GET, "/b"));
    }

    #[test]
    fn should_reject_empty_role_key_in_json() {
        let json = r#"{"rules": {"": [{"method": "GET", "path": "/users"}]}}"#;

        let error = err_of(parse_rules(json));

        assert!(error.contains("invalid rules content"), "got: {error}");
        assert!(error.contains(r#"role "" is empty"#), "got: {error}");
    }

    #[test]
    fn should_include_role_and_rule_index_in_endpoint_error() {
        let d = dto(
            vec![],
            vec![
                ("admin", vec![ep("GET", "/users")]),
                ("user", vec![ep("GET", "/ok"), ep("GET FOO", "/orders")]),
            ],
        );

        let error = err_of(RuleSet::try_from(d));

        assert!(error.contains(r#"role "user", rule #1"#), "got: {error}");
        assert!(error.contains("invalid method"), "got: {error}");
    }

    #[test]
    fn should_count_rule_index_per_role() {
        // у user это первое правило, поэтому #0, а не сквозной номер
        let d = dto(
            vec![],
            vec![
                ("admin", vec![ep("GET", "/users")]),
                ("user", vec![ep("GET", "a")]),
            ],
        );

        let error = err_of(RuleSet::try_from(d));

        assert!(error.contains(r#"role "user", rule #0"#), "got: {error}");
        assert!(error.contains("must start with '/'"), "got: {error}");
    }

    #[test]
    fn should_accept_empty_dto() {
        let result = RuleSet::try_from(dto(vec![], vec![])).unwrap();

        assert!(result.roles.is_empty());
        assert!(result.public.is_empty());
    }

    /// Фиксирует ТЕКУЩЕЕ поведение: роль без правил в `roles` не попадает.
    #[test]
    fn role_without_endpoints_is_not_stored() {
        let result = RuleSet::try_from(dto(vec![], vec![("viewer", vec![])])).unwrap();

        assert!(!result.roles.contains_key("viewer"));
    }

    // ---------- RuleSet::try_from: public ----------

    #[test]
    fn should_collect_public_endpoints() {
        let d = dto(
            vec![ep("GET", "/health/live"), ep("*", "/static/**")],
            vec![("admin", vec![ep("GET", "/users")])],
        );

        let result = RuleSet::try_from(d).unwrap();

        assert_eq!(result.public.len(), 2);
        assert!(result.public[0].matches(&Method::GET, "/health/live"));
        assert!(result.public[1].matches(&Method::POST, "/static/a/b"));
        // публичные правила не смешиваются с ролями
        assert_eq!(result.roles.len(), 1);
        assert_eq!(result.roles["admin"].len(), 1);
    }

    #[test]
    fn should_return_error_with_index_for_invalid_public_rule() {
        let d = dto(
            vec![ep("GET", "/ok"), ep("GET", "a")],
            vec![("admin", vec![ep("GET", "/users")])],
        );

        let error = err_of(RuleSet::try_from(d));

        assert!(error.starts_with("public rule #1"), "got: {error}");
    }

    // ---------- JSON: разбор RulesDto ----------

    #[test]
    fn should_parse_json_and_check_access() {
        let json = r#"{
            "rules": {
                "admin": [{"method": "GET", "path": "/users"}],
                "user":  [{"method": "POST", "path": "/orders"}]
            }
        }"#;

        let rules = RuleSet::try_from(from_str::<RulesDto>(json).unwrap()).unwrap();

        assert!(rules.is_allowed(&["admin".into()], &Method::GET, "/users"));
        assert!(rules.is_allowed(&["user".into()], &Method::POST, "/orders"));
        assert!(!rules.is_allowed(&["user".into()], &Method::GET, "/users"));
        assert!(!rules.is_allowed(&["guest".into()], &Method::GET, "/users"));
    }

    #[test]
    fn public_section_is_optional() {
        let json = r#"{"rules": {"admin": [{"method": "GET", "path": "/users"}]}}"#;

        let d = from_str::<RulesDto>(json).unwrap();

        assert!(d.public.is_empty());
    }

    #[test]
    fn should_parse_public_section() {
        let json = r#"{
            "public": [{"method": "GET", "path": "/health/live"}],
            "rules": {"admin": [{"method": "GET", "path": "/users"}]}
        }"#;

        let rules = parse_rules(json).unwrap();

        assert_eq!(rules.public.len(), 1);
        assert_eq!(rules.roles.len(), 1);
    }

    #[test]
    fn should_reject_json_without_rules_key() {
        assert!(from_str::<RulesDto>("{}").is_err());
        assert!(from_str::<RulesDto>(r#"{"public": []}"#).is_err());
    }

    #[test]
    fn should_reject_json_without_path() {
        let json = r#"{"rules": {"admin": [{"method": "GET"}]}}"#;

        assert!(from_str::<RulesDto>(json).is_err());
    }

    #[test]
    fn should_reject_json_without_method() {
        let json = r#"{"rules": {"admin": [{"path": "/users"}]}}"#;

        assert!(from_str::<RulesDto>(json).is_err());
    }

    #[test]
    fn should_reject_unknown_field_in_endpoint() {
        let json = r#"{"rules": {"admin": [
            {"method": "GET", "path": "/users", "effect": "ALLOW"}
        ]}}"#;

        let error = err_of(parse_rules(json));

        assert!(error.contains("invalid rules JSON"), "got: {error}");
    }

    #[test]
    fn should_reject_unknown_top_level_field() {
        let json = r#"{"rules": {"admin": [{"method": "GET", "path": "/users"}]}, "version": 1}"#;

        let error = err_of(parse_rules(json));

        assert!(error.contains("invalid rules JSON"), "got: {error}");
    }

    #[test]
    fn should_reject_legacy_array_format() {
        let json = r#"{"rules": [{"role": "admin", "method": "GET", "path": "/users"}]}"#;

        let error = err_of(parse_rules(json));

        assert!(error.contains("invalid rules JSON"), "got: {error}");
    }

    // ---------- parse_rules ----------

    #[test]
    fn should_parse_valid_rules_json() {
        let json = r#"{"rules": {"admin": [{"method": "GET", "path": "/users"}]}}"#;

        let rules = parse_rules(json).unwrap();

        assert_eq!(rules.roles.len(), 1);
        assert_eq!(rules.roles["admin"].len(), 1);
    }

    #[test]
    fn should_reject_invalid_json() {
        let error = err_of(parse_rules(r#"{"rules": {"#));

        assert!(error.contains("invalid rules JSON"), "got: {error}");
    }

    #[test]
    fn should_wrap_content_error_with_role_and_index() {
        let json = r#"{"rules": {"admin": [{"method": "GET", "path": "a"}]}}"#;

        let error = err_of(parse_rules(json));

        assert!(error.contains("invalid rules content"), "got: {error}");
        assert!(error.contains(r#"role "admin", rule #0"#), "got: {error}");
    }

    #[test]
    fn should_return_error_for_empty_or_blank_role() {
        for role in ["", "   ", "\t"] {
            let d = dto(vec![], vec![(role, vec![ep("GET", "/users")])]);

            let error = err_of(RuleSet::try_from(d));

            assert!(
                error.contains(&format!("role {role:?} is empty")),
                "role {role:?}, got: {error}"
            );
        }
    }

    #[test]
    fn should_reject_empty_rules() {
        let error = err_of(parse_rules(r#"{"rules": {}}"#));

        assert_eq!(error, "rules source returned no rules");
    }

    /// Фиксирует ТЕКУЩЕЕ поведение: набор только из `public` без ролей отвергается.
    /// Если решишь это разрешить, поменяй проверку в parse_rules и этот тест.
    #[test]
    fn should_reject_public_only_without_roles() {
        let json = r#"{
            "public": [{"method": "GET", "path": "/health/live"}],
            "rules": {}
        }"#;

        let error = err_of(parse_rules(json));

        assert_eq!(error, "rules source returned no rules");
    }

    // ---------- HttpRulesSource ----------

    #[test]
    fn http_source_can_be_created() {
        let client = HttpClient::new().unwrap();

        let _ = HttpRulesSource::new(client, "http://127.0.0.1:9000/rules.json".to_string());
    }

    /// Регрессия на утечку секрета: порт 1 на localhost закрыт, соединение отклоняется,
    /// а токен из query не должен попасть в текст ошибки.
    #[tokio::test]
    async fn load_error_does_not_leak_url() {
        let client = HttpClient::new().unwrap();
        let src = HttpRulesSource::new(client, "http://127.0.0.1:1/rules?token=SECRET".to_string());

        let error = err_of(src.load().await);

        assert!(
            error.contains("rules source request failed"),
            "got: {error}"
        );
        assert!(
            !error.contains("SECRET"),
            "URL просочился в ошибку: {error}"
        );
    }

    #[test]
    fn should_parse_new_format_and_match_public_endpoints() {
        let json = r#"{
        "public": [{"method": "POST", "path": "/auth/login"}],
        "rules": {
            "admin": [{"method": "GET", "path": "/api/users"}]
        }
    }"#;

        let rules = parse_rules(json).unwrap();

        assert!(rules.is_public(&Method::POST, "/auth/login"));
        assert!(!rules.is_public(&Method::GET, "/auth/login"));
        assert!(!rules.is_public(&Method::POST, "/api/x"));
    }

    #[test]
    fn should_parse_rules_without_public_field() {
        let json = r#"{
        "rules": {
            "admin": [{"method": "GET", "path": "/users"}]
        }
    }"#;

        let rules = parse_rules(json).unwrap();

        assert!(rules.public.is_empty());
        assert_eq!(rules.roles.len(), 1);
    }

    #[test]
    fn should_allow_role_without_rules_in_dto_conversion() {
        let dto = dto(vec![], vec![("guest", vec![])]);

        let rules = RuleSet::try_from(dto).unwrap();

        assert!(!rules.roles.contains_key("guest"));
    }

    #[test]
    fn should_reject_rules_without_any_role_rules() {
        let json = r#"{"rules": {"guest": []}}"#;

        let error = err_of(parse_rules(json));

        assert_eq!(error, "rules source returned no rules");
    }

    #[test]
    fn should_reject_unknown_field_in_endpoint_dto() {
        let json = r#"{
        "rules": {
            "admin": [{
                "method": "GET",
                "path": "/users",
                "effect": "ALLOW"
            }]
        }
    }"#;

        assert!(from_str::<RulesDto>(json).is_err());
    }

    #[test]
    fn should_reject_legacy_role_field_in_rule() {
        let json = r#"{
        "rules": {
            "admin": [{
                "role": "admin",
                "method": "GET",
                "path": "/users"
            }]
        }
    }"#;

        assert!(from_str::<RulesDto>(json).is_err());
    }

    #[test]
    fn should_reject_role_instead_of_rules_field() {
        let json = r#"{
        "role": {
            "admin": [{"method": "GET", "path": "/users"}]
        }
    }"#;

        assert!(from_str::<RulesDto>(json).is_err());
    }
}
