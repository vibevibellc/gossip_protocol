use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Instant,
};

use anyhow::{Result, anyhow, bail};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use tokio::net::lookup_host;
use url::Url;

use crate::protocol::{
    AssertionResult, HealthCheckSpec, HealthHttpMethod, MAX_BODY_SAMPLE_BYTES, ResponseAssertion,
    validate_health_check_spec,
};

#[derive(Debug, Clone)]
pub struct HealthExecution {
    pub response_status: Option<u16>,
    pub latency_ms: u64,
    pub success: bool,
    pub assertion_results: Vec<AssertionResult>,
    pub response_headers: BTreeMap<String, String>,
    pub response_body_sample: Option<String>,
    pub error: Option<String>,
}

pub async fn execute_health_check(spec: &HealthCheckSpec) -> HealthExecution {
    match execute_inner(spec).await {
        Ok(outcome) => outcome,
        Err(error) => HealthExecution {
            response_status: None,
            latency_ms: 0,
            success: false,
            assertion_results: Vec::new(),
            response_headers: BTreeMap::new(),
            response_body_sample: None,
            error: Some(error.to_string()),
        },
    }
}

async fn execute_inner(spec: &HealthCheckSpec) -> Result<HealthExecution> {
    validate_health_check_spec(spec)?;

    let mut url = Url::parse(&spec.url)?;
    if url.scheme() != "https" && !spec.allow_insecure_http {
        bail!("health checks require https unless allow_insecure_http is true");
    }

    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in &spec.query {
            pairs.append_pair(key, value);
        }
    }

    if !spec.allow_private_targets {
        enforce_public_target_policy(&url).await?;
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(spec.timeout_ms))
        .build()?;

    let mut headers = HeaderMap::new();
    for (key, value) in &spec.headers {
        headers.insert(
            HeaderName::from_bytes(key.as_bytes())?,
            HeaderValue::from_str(value)?,
        );
    }

    let start = Instant::now();
    let request = match spec.method {
        HealthHttpMethod::Get => client.get(url),
        HealthHttpMethod::Head => client.head(url),
        HealthHttpMethod::Post => client.post(url),
    }
    .headers(headers);

    let request = if matches!(spec.method, HealthHttpMethod::Post) {
        if let Some(body) = &spec.body_json {
            request.json(body)
        } else {
            request
        }
    } else {
        request
    };

    let response = request.send().await?;
    let latency_ms = start.elapsed().as_millis() as u64;
    let status = response.status().as_u16();
    let response_headers = simplify_headers(response.headers());
    let body = if matches!(spec.method, HealthHttpMethod::Head) {
        None
    } else {
        Some(response.text().await?)
    };

    let body_sample = body.as_deref().map(truncate_body);
    let parsed_json = body
        .as_deref()
        .and_then(|text| serde_json::from_str::<Value>(text).ok());
    let assertion_results = evaluate_assertions(
        spec,
        &response_headers,
        body.as_deref(),
        parsed_json.as_ref(),
    );

    let expected_status_ok = spec
        .expected_status
        .map(|expected| expected == status)
        .unwrap_or(true);
    let all_assertions_ok = assertion_results.iter().all(|result| result.passed);
    let success = expected_status_ok && all_assertions_ok;

    Ok(HealthExecution {
        response_status: Some(status),
        latency_ms,
        success,
        assertion_results,
        response_headers,
        response_body_sample: body_sample,
        error: None,
    })
}

async fn enforce_public_target_policy(url: &Url) -> Result<()> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("health check url must include a host"))?;
    if is_disallowed_hostname(host) {
        bail!("health check target host is not allowed");
    }

    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("health check target port is invalid"))?;
    let resolved: Vec<_> = lookup_host((host, port)).await?.collect();
    if resolved.is_empty() {
        bail!("health check target did not resolve to any addresses");
    }
    if resolved
        .iter()
        .any(|socket_addr| is_disallowed_ip(socket_addr.ip()))
    {
        bail!("health check target resolved to a private or local address");
    }
    Ok(())
}

fn is_disallowed_hostname(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".localhost")
}

fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || is_documentation_ipv4(ip)
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || is_documentation_ipv6(ip)
                || ip
                    .to_ipv4_mapped()
                    .map(|ipv4| is_disallowed_ip(IpAddr::V4(ipv4)))
                    .unwrap_or(false)
        }
    }
}

fn is_documentation_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    matches!(
        octets,
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
    )
}

fn is_documentation_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn simplify_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(key, value)| {
            value
                .to_str()
                .ok()
                .map(|header_value| (key.to_string(), header_value.to_string()))
        })
        .collect()
}

fn truncate_body(body: &str) -> String {
    let bytes = body.as_bytes();
    if bytes.len() <= MAX_BODY_SAMPLE_BYTES {
        return body.to_string();
    }

    String::from_utf8_lossy(&bytes[..MAX_BODY_SAMPLE_BYTES]).to_string()
}

fn evaluate_assertions(
    spec: &HealthCheckSpec,
    headers: &BTreeMap<String, String>,
    body: Option<&str>,
    json: Option<&Value>,
) -> Vec<AssertionResult> {
    spec.assertions
        .iter()
        .map(|assertion| match assertion {
            ResponseAssertion::JsonFieldExists { path } => {
                let found = json.and_then(|value| find_json_path(value, path)).is_some();
                AssertionResult {
                    assertion: assertion.clone(),
                    passed: found,
                    detail: if found {
                        format!("json path {path} exists")
                    } else {
                        format!("json path {path} is missing")
                    },
                }
            }
            ResponseAssertion::JsonFieldEquals { path, value } => {
                let observed = json.and_then(|candidate| find_json_path(candidate, path));
                let passed = observed
                    .map(|candidate| candidate == value)
                    .unwrap_or(false);
                AssertionResult {
                    assertion: assertion.clone(),
                    passed,
                    detail: if let Some(observed) = observed {
                        format!("expected {value} and observed {observed}")
                    } else {
                        format!("json path {path} is missing")
                    },
                }
            }
            ResponseAssertion::HeaderEquals { name, value } => {
                let observed = headers
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.as_str());
                let passed = observed
                    .map(|candidate| candidate == value)
                    .unwrap_or(false);
                AssertionResult {
                    assertion: assertion.clone(),
                    passed,
                    detail: if let Some(observed) = observed {
                        format!("expected header {name}={value} and observed {observed}")
                    } else {
                        format!("header {name} is missing")
                    },
                }
            }
            ResponseAssertion::BodyContains { text } => {
                let passed = body
                    .map(|candidate| candidate.contains(text))
                    .unwrap_or(false);
                AssertionResult {
                    assertion: assertion.clone(),
                    passed,
                    detail: if passed {
                        format!("body contains {text}")
                    } else {
                        format!("body does not contain {text}")
                    },
                }
            }
        })
        .collect()
}

fn find_json_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = match current {
            Value::Object(map) => map.get(segment)?,
            Value::Array(items) => {
                let index: usize = segment.parse().ok()?;
                items.get(index)?
            }
            _ => return None,
        };
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use axum::{
        Json, Router,
        http::HeaderMap,
        routing::{get, post},
    };
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::*;
    use crate::protocol::{HealthCheckSpec, ResponseAssertion};

    #[tokio::test]
    async fn health_check_passes_headers_query_and_assertions() -> Result<()> {
        async fn handler() -> Json<Value> {
            Json(json!({
                "ready": true,
                "service": {
                    "name": "demo"
                }
            }))
        }

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            let app = Router::new().route("/health", get(handler));
            axum::serve(listener, app).await.unwrap();
        });

        let mut headers = BTreeMap::new();
        headers.insert("x-demo-key".into(), "secret".into());

        let mut query = BTreeMap::new();
        query.insert("region".into(), "us".into());

        let spec = HealthCheckSpec {
            request_id: "request-1".into(),
            url: format!("http://{addr}/health"),
            method: HealthHttpMethod::Get,
            headers,
            query,
            timeout_ms: 2_000,
            expected_status: Some(200),
            assertions: vec![
                ResponseAssertion::JsonFieldEquals {
                    path: "ready".into(),
                    value: Value::Bool(true),
                },
                ResponseAssertion::JsonFieldExists {
                    path: "service.name".into(),
                },
            ],
            body_json: None,
            allow_insecure_http: true,
            allow_private_targets: true,
        };

        let outcome = execute_health_check(&spec).await;
        assert!(outcome.success);
        assert_eq!(outcome.response_status, Some(200));
        assert_eq!(outcome.assertion_results.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn post_health_check_supports_json_body_and_header_assertions() -> Result<()> {
        async fn handler(headers: HeaderMap, Json(payload): Json<Value>) -> Json<Value> {
            let token = headers
                .get("x-health-key")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("missing");
            Json(json!({
                "accepted": true,
                "echo": payload,
                "token": token
            }))
        }

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            let app = Router::new().route("/health", post(handler));
            axum::serve(listener, app).await.unwrap();
        });

        let mut headers = BTreeMap::new();
        headers.insert("x-health-key".into(), "post-secret".into());

        let spec = HealthCheckSpec {
            request_id: "request-post".into(),
            url: format!("http://{addr}/health"),
            method: HealthHttpMethod::Post,
            headers,
            query: BTreeMap::new(),
            timeout_ms: 2_000,
            expected_status: Some(200),
            assertions: vec![
                ResponseAssertion::JsonFieldEquals {
                    path: "accepted".into(),
                    value: Value::Bool(true),
                },
                ResponseAssertion::JsonFieldEquals {
                    path: "echo.mode".into(),
                    value: Value::String("stress".into()),
                },
                ResponseAssertion::JsonFieldEquals {
                    path: "token".into(),
                    value: Value::String("post-secret".into()),
                },
            ],
            body_json: Some(json!({
                "mode": "stress",
                "request": 7
            })),
            allow_insecure_http: true,
            allow_private_targets: true,
        };

        let outcome = execute_health_check(&spec).await;
        assert!(outcome.success);
        assert_eq!(outcome.response_status, Some(200));
        assert_eq!(outcome.assertion_results.len(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn head_health_check_and_timeout_failures_are_reported() -> Result<()> {
        async fn head_handler() -> &'static str {
            ""
        }

        async fn slow_handler() -> Json<Value> {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            Json(json!({ "ready": true }))
        }

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            let app = Router::new()
                .route("/head-health", get(head_handler))
                .route("/slow-health", get(slow_handler));
            axum::serve(listener, app).await.unwrap();
        });

        let head_spec = HealthCheckSpec {
            request_id: "request-head".into(),
            url: format!("http://{addr}/head-health"),
            method: HealthHttpMethod::Head,
            headers: BTreeMap::new(),
            query: BTreeMap::new(),
            timeout_ms: 2_000,
            expected_status: Some(200),
            assertions: Vec::new(),
            body_json: None,
            allow_insecure_http: true,
            allow_private_targets: true,
        };
        let head_outcome = execute_health_check(&head_spec).await;
        assert!(head_outcome.success);
        assert_eq!(head_outcome.response_status, Some(200));
        assert!(head_outcome.response_body_sample.is_none());

        let slow_spec = HealthCheckSpec {
            request_id: "request-timeout".into(),
            url: format!("http://{addr}/slow-health"),
            method: HealthHttpMethod::Get,
            headers: BTreeMap::new(),
            query: BTreeMap::new(),
            timeout_ms: 50,
            expected_status: Some(200),
            assertions: Vec::new(),
            body_json: None,
            allow_insecure_http: true,
            allow_private_targets: true,
        };
        let slow_outcome = execute_health_check(&slow_spec).await;
        assert!(!slow_outcome.success);
        assert!(slow_outcome.error.is_some());
        assert_eq!(slow_outcome.response_status, None);
        Ok(())
    }

    #[tokio::test]
    async fn private_targets_are_blocked_by_default() -> Result<()> {
        let spec = HealthCheckSpec {
            request_id: "request-private-block".into(),
            url: "http://127.0.0.1:9999/health".into(),
            method: HealthHttpMethod::Get,
            headers: BTreeMap::new(),
            query: BTreeMap::new(),
            timeout_ms: 1_000,
            expected_status: Some(200),
            assertions: Vec::new(),
            body_json: None,
            allow_insecure_http: true,
            allow_private_targets: false,
        };

        let outcome = execute_health_check(&spec).await;
        assert!(!outcome.success);
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("target")
        );
        Ok(())
    }
}
