use jsonwebtoken::Algorithm;
use thiserror::Error;

pub struct Config {
    pub bind_addr: String,
    pub jwks_url: String,
    pub rules_url: String,
    pub upstream_url: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub rules_refresh_secs: u64,
    pub jwks_refresh_secs: u64,
    pub jwt_algorithms: Vec<Algorithm>,
    pub max_body_bytes: usize,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing env var {0}")]
    Missing(&'static str),

    #[error("{name}: {reason}")]
    Invalid { name: &'static str, reason: String },
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    std::env::var(name).map_err(|_| ConfigError::Missing(name))
}

fn env_or<T>(name: &'static str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
{
    match std::env::var(name) {
        Ok(value) => value.parse().map_err(|_| ConfigError::Invalid {
            name,
            reason: "invalid value".to_string(),
        }),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(_) => Err(ConfigError::Invalid {
            name,
            reason: "failed to read env var".to_string(),
        }),
    }
}

fn parse_algorithms(raw: &str) -> Result<Vec<Algorithm>, ConfigError> {
    let algs = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let alg = s.parse::<Algorithm>().map_err(|e| ConfigError::Invalid {
                name: "JWT_ALGORITHMS",
                reason: format!("invalid algorithm {s:?}: {e}"),
            })?;

            if matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
                return Err(ConfigError::Invalid {
                    name: "JWT_ALGORITHMS",
                    reason: format!("symmetric algorithm {s:?} is not allowed"),
                });
            }

            Ok(alg)
        })
        .collect::<Result<Vec<_>, ConfigError>>()?;

    if algs.is_empty() {
        return Err(ConfigError::Invalid {
            name: "JWT_ALGORITHMS",
            reason: "list is empty".to_string(),
        });
    }

    Ok(algs)
}

fn mb_to_bytes(mb: u64) -> Result<usize, ConfigError> {
    if mb == 0 {
        return Err(ConfigError::Invalid {
            name: "MAX_BODY_MB",
            reason: "must be > 0".to_string(),
        });
    }

    mb.checked_mul(1024 * 1024)
        .and_then(|b| usize::try_from(b).ok())
        .ok_or_else(|| ConfigError::Invalid {
            name: "MAX_BODY_MB",
            reason: "value is too large".to_string(),
        })
}

fn positive(name: &'static str, v: u64) -> Result<u64, ConfigError> {
    if v == 0 {
        Err(ConfigError::Invalid {
            name,
            reason: "must be > 0".to_string(),
        })
    } else {
        Ok(v)
    }
}

impl Config {
    pub fn from_env() -> Result<Config, ConfigError> {
        Ok(Config {
            bind_addr: env_or("BIND_ADDR", "0.0.0.0:8080".into())?,
            jwks_url: required("JWKS_URL")?,
            rules_url: required("RULES_URL")?,
            upstream_url: required("UPSTREAM_URL")?,
            jwt_issuer: required("JWT_ISSUER")?,
            jwt_audience: required("JWT_AUDIENCE")?,
            rules_refresh_secs: positive("RULES_REFRESH_SECS", env_or("RULES_REFRESH_SECS", 60)?)?,
            jwks_refresh_secs: positive("JWKS_REFRESH_SECS", env_or("JWKS_REFRESH_SECS", 300)?)?,
            jwt_algorithms: parse_algorithms(
                &std::env::var("JWT_ALGORITHMS").unwrap_or_else(|_| "RS256".to_string()),
            )?,
            max_body_bytes: mb_to_bytes(env_or("MAX_BODY_MB", 10u64)?)?,
        })
    }
}
