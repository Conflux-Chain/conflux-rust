use http::{HeaderValue, Method};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

/// Error thrown when parsing cors domains went wrong
#[derive(Debug, thiserror::Error)]
pub enum CorsDomainError {
    /// Represents an invalid header value for a domain
    #[error("{domain} is an invalid header value")]
    InvalidHeader {
        /// The domain that caused the invalid header
        domain: String,
    },

    /// Indicates that a wildcard origin was used incorrectly in a list
    #[error(
        "wildcard origin (`*`) cannot be passed as part of a list: {input}"
    )]
    WildCardNotAllowed {
        /// The input string containing the incorrectly used wildcard
        input: String,
    },
}

/// Creates a [`CorsLayer`] from the given domains
pub fn create_cors_layer(
    http_cors_domains: &str,
) -> Result<CorsLayer, CorsDomainError> {
    let cors = match http_cors_domains.trim() {
        "*" | "all" => CorsLayer::new()
            .allow_methods([Method::GET, Method::POST])
            .allow_origin(Any)
            .allow_headers(Any),
        _ => {
            let iter = http_cors_domains.split(',').map(str::trim);
            if iter.clone().any(|o| o == "*" || o == "all") {
                return Err(CorsDomainError::WildCardNotAllowed {
                    input: http_cors_domains.to_string(),
                });
            }

            let origins = iter
                .map(|domain| {
                    domain.parse::<HeaderValue>().map_err(|_| {
                        CorsDomainError::InvalidHeader {
                            domain: domain.to_string(),
                        }
                    })
                })
                .collect::<Result<Vec<HeaderValue>, _>>()?;

            let origin = AllowOrigin::list(origins);
            CorsLayer::new()
                .allow_methods([Method::GET, Method::POST])
                .allow_origin(origin)
                .allow_headers(Any)
        }
    };
    Ok(cors)
}

/// Creates the [`CorsLayer`] if any, returning `None` for `"none"` input
pub fn maybe_cors_layer(
    cors: Option<String>,
) -> Result<Option<CorsLayer>, CorsDomainError> {
    if cors.as_deref() == Some("none") {
        return Ok(None);
    }
    cors.as_deref().map(create_cors_layer).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_with_spaces_rejected() {
        // Wildcard with leading space should still be rejected
        let result = create_cors_layer("http://example.com, *");
        assert!(matches!(
            result,
            Err(CorsDomainError::WildCardNotAllowed { .. })
        ));
    }
}
