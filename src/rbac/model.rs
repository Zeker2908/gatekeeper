use crate::rbac::pattern::PatternError;
use http::Method;
use std::collections::HashMap;
use thiserror::Error;

/// Ошибки преобразования `RulesDto` в `RuleSet`.
#[derive(Debug, Error)]
pub enum RulesError {
    #[error("role {role:?} is empty")]
    EmptyRole { role: String },

    #[error("role {role:?}, rule #{index}: {source}")]
    InvalidRule {
        role: String,
        index: usize,
        #[source]
        source: PatternError,
    },

    #[error("public rule #{index}: {source}")]
    InvalidPublicRule {
        index: usize,
        #[source]
        source: PatternError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    Literal(String),
    Param,
    Rest,
}

#[derive(Debug, Clone)]
pub struct PathPattern {
    pub(super) segments: Vec<Segment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodMatch {
    Any,
    Exact(Method),
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub(super) method: MethodMatch,
    pub(super) pattern: PathPattern,
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub(super) roles: HashMap<String, Vec<Endpoint>>, // роль -> разрешённые эндпоинты
    pub(super) public: Vec<Endpoint>,
}
