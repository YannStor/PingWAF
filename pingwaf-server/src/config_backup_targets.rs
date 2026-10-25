//! Upload destinations for encrypted backups: generic S3 and GitHub.
//!
//! Both clients see only the encrypted envelope. Errors deliberately carry a
//! status and operation, not a URL with credentials or a provider response that
//! might echo secret configuration.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use reqwest::{Method, StatusCode, Url};
use ring::digest::{digest, SHA256};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::config_backup_crypto::BackupError;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

fn required<'a>(config: &'a Value, key: &str) -> Result<&'a str, BackupError> {
    config
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            BackupError::Format(format!("backup target requires {key}"))
        })
}

fn optional<'a>(config: &'a Value, key: &str, default: &'a str) -> &'a str {
    config
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hmac(key: &[u8], value: &str) -> Result<Vec<u8>, BackupError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| {
        BackupError::Operation("could not initialise HMAC".into())
    })?;
    mac.update(value.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn client() -> Result<reqwest::Client, BackupError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| BackupError::Operation(error.to_string()))
}

fn canonical_query(url: &Url) -> String {
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(key, value)| {
            (
                urlencoding::encode(&key).into_owned(),
                urlencoding::encode(&value).into_owned(),
            )
        })
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn s3_url(
    config: &Value,
    key: Option<&str>,
    list_bucket: bool,
) -> Result<Url, BackupError> {
    let endpoint = required(config, "endpoint")?;
    let bucket = required(config, "bucket")?;
    let path_style = config
        .get("path_style")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let prefix = optional(config, "prefix", "").trim_matches('/');
    let mut url = Url::parse(endpoint)
        .map_err(|_| BackupError::Format("invalid S3 endpoint".into()))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(BackupError::Format(
            "S3 endpoint must be an absolute HTTP(S) URL".into(),
        ));
    }
    if url.query_pairs().next().is_some() {
        return Err(BackupError::Format(
            "S3 endpoint must not contain a query string".into(),
        ));
    }
    if !path_style {
        let host = url.host_str().ok_or_else(|| {
            BackupError::Format("S3 endpoint has no host".into())
        })?;
        url.set_host(Some(&format!("{bucket}.{host}")))
            .map_err(|_| {
                BackupError::Format("invalid virtual-hosted S3 endpoint".into())
            })?;
    }
    let base = url.path().trim_end_matches('/').to_string();
    let path = if path_style {
        format!("{base}/{bucket}")
    } else {
        base
    };
    let key = key.map(|key| {
        let key = key.trim_start_matches('/');
        if prefix.is_empty() {
            key.to_string()
        } else {
            format!("{prefix}/{key}")
        }
    });
    let path = match (key, list_bucket) {
        (Some(key), false) => format!("{path}/{key}"),
        _ => format!("{path}/"),
    };
    url.set_path(&path);
    Ok(url)
}

async fn s3_request(
    config: &Value,
    method: Method,
    key: Option<&str>,
    list_bucket: bool,
    body: Vec<u8>,
) -> Result<StatusCode, BackupError> {
    let mut url = s3_url(config, key, list_bucket)?;
    if list_bucket {
        url.query_pairs_mut()
            .append_pair("list-type", "2")
            .append_pair("max-keys", "1");
    }
    let payload_hash = hex(digest(&SHA256, &body).as_ref());
    let timestamp = chrono::Utc::now();
    let amz_date = timestamp.format("%Y%m%dT%H%M%SZ").to_string();
    let short_date = timestamp.format("%Y%m%d").to_string();
    let region = optional(config, "region", "us-east-1");
    let host = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_string(),
    };
    let canonical_headers = format!(
        "host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_query = canonical_query(&url);
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        url.path(),
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_hash
    );
    let scope = format!("{short_date}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(digest(&SHA256, canonical.as_bytes()).as_ref())
    );
    let secret = required(config, "secret_access_key")?;
    let access_key = required(config, "access_key_id")?;
    let date_key = hmac(format!("AWS4{secret}").as_bytes(), &short_date)?;
    let region_key = hmac(&date_key, region)?;
    let service_key = hmac(&region_key, "s3")?;
    let signing_key = hmac(&service_key, "aws4_request")?;
    let signature = hex(&hmac(&signing_key, &string_to_sign)?);
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let response = client()?
        .request(method, url)
        .header("host", host)
        .header("x-amz-content-sha256", payload_hash)
        .header("x-amz-date", amz_date)
        .header("authorization", authorization)
        .body(body)
        .send()
        .await
        .map_err(|_| BackupError::Operation("S3 request failed".into()))?;
    Ok(response.status())
}

fn github_url(config: &Value, path: &str) -> Result<Url, BackupError> {
    let api = optional(config, "api_url", "https://api.github.com");
    let mut url = Url::parse(api)
        .map_err(|_| BackupError::Format("invalid GitHub API URL".into()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(BackupError::Format(
            "GitHub API URL must use HTTP(S)".into(),
        ));
    }
    let repository = required(config, "repository")?;
    let mut parts = repository.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default();
    if owner.is_empty() || repo.is_empty() || parts.next().is_some() {
        return Err(BackupError::Format(
            "GitHub repository must be owner/repo".into(),
        ));
    }
    {
        let mut segments = url.path_segments_mut().map_err(|_| {
            BackupError::Format("invalid GitHub API base URL".into())
        })?;
        segments.push("repos").push(owner).push(repo);
        for segment in path.trim_matches('/').split('/') {
            if !segment.is_empty() {
                segments.push(segment);
            }
        }
    }
    Ok(url)
}

async fn github_request(
    config: &Value,
    method: Method,
    path: &str,
    body: Option<Value>,
    read_body: bool,
) -> Result<(StatusCode, Option<Value>), BackupError> {
    let token = required(config, "token")?;
    let mut url = github_url(config, path)?;
    if method == Method::GET && path.starts_with("contents/") {
        url.query_pairs_mut()
            .append_pair("ref", optional(config, "branch", "main"));
    }
    let mut request = client()?
        .request(method, url)
        .header("authorization", format!("Bearer {token}"))
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "pingwaf-config-backup")
        .header("x-github-api-version", "2022-11-28");
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|_| BackupError::Operation("GitHub request failed".into()))?;
    let status = response.status();
    if !read_body {
        return Ok((status, None));
    }
    if response
        .content_length()
        .is_some_and(|size| size as usize > MAX_RESPONSE_BYTES)
    {
        return Err(BackupError::Limit);
    }
    let bytes = response.bytes().await.map_err(|_| {
        BackupError::Operation("could not read GitHub response".into())
    })?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(BackupError::Limit);
    }
    let value = serde_json::from_slice(&bytes).map_err(|_| {
        BackupError::Operation("invalid GitHub JSON response".into())
    })?;
    Ok((status, Some(value)))
}

fn ensure(status: StatusCode, operation: &str) -> Result<(), BackupError> {
    if status.is_success() {
        return Ok(());
    }
    Err(BackupError::Operation(format!(
        "{operation} failed with HTTP {status}"
    )))
}

pub async fn test_target(
    kind: &str,
    config: &Value,
) -> Result<(), BackupError> {
    match kind {
        "s3" => {
            let status =
                s3_request(config, Method::GET, None, true, Vec::new()).await?;
            ensure(status, "S3 bucket check")
        },
        "github" => {
            let (status, _) =
                github_request(config, Method::GET, "", None, true).await?;
            ensure(status, "GitHub repository check")
        },
        _ => Err(BackupError::Format("unknown backup target kind".into())),
    }
}

pub async fn upload_to_target(
    kind: &str,
    config: &Value,
    file_name: &str,
    payload: &[u8],
) -> Result<String, BackupError> {
    match kind {
        "s3" => {
            let status = s3_request(
                config,
                Method::PUT,
                Some(file_name),
                false,
                payload.to_vec(),
            )
            .await?;
            ensure(status, "S3 backup upload")?;
            let prefix = optional(config, "prefix", "").trim_matches('/');
            let key = if prefix.is_empty() {
                file_name.to_string()
            } else {
                format!("{prefix}/{file_name}")
            };
            Ok(format!("s3://{}/{}", required(config, "bucket")?, key))
        },
        "github" => {
            let prefix =
                optional(config, "prefix", "config-backups").trim_matches('/');
            let path = format!("contents/{prefix}/{file_name}");
            let branch = optional(config, "branch", "main");
            let body = json!({
                "message": format!("PingWAF configuration backup {file_name}"),
                "content": B64.encode(payload),
                "branch": branch,
            });
            let (status, _) = github_request(
                config,
                Method::PUT,
                &path,
                Some(body.clone()),
                false,
            )
            .await?;
            if status.is_success() {
                return Ok(format!(
                    "github:{}:{path}",
                    required(config, "repository")?
                ));
            }
            if status != StatusCode::CONFLICT
                && status != StatusCode::UNPROCESSABLE_ENTITY
            {
                return ensure(status, "GitHub backup upload")
                    .map(|_| String::new());
            }
            // A file with the same generated name may already exist. Include
            // its SHA to turn the create into an update rather than failing.
            let (read_status, existing) =
                github_request(config, Method::GET, &path, None, true).await?;
            if read_status != StatusCode::NOT_FOUND {
                ensure(read_status, "GitHub existing-backup check")?;
            }
            let sha = existing.and_then(|value| {
                value.get("sha").and_then(Value::as_str).map(str::to_string)
            });
            let body = match sha {
                Some(sha) => {
                    let mut body = body;
                    body["sha"] = json!(sha);
                    body
                },
                None => body,
            };
            let (status, _) =
                github_request(config, Method::PUT, &path, Some(body), false)
                    .await?;
            ensure(status, "GitHub backup update")?;
            Ok(format!("github:{}:{path}", required(config, "repository")?))
        },
        _ => Err(BackupError::Format("unknown backup target kind".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_urls_support_custom_path_style_endpoints() {
        let config = json!({
            "endpoint": "http://127.0.0.1:9000",
            "bucket": "backups",
            "prefix": "prod",
            "path_style": true,
        });
        let url =
            s3_url(&config, Some("backup.json"), false).expect("valid URL");
        assert_eq!(url.path(), "/backups/prod/backup.json");
    }

    #[test]
    fn sigv4_query_is_sorted_and_percent_encoded() {
        let url =
            Url::parse("https://example.com/bucket?z=last&a=hello%20world")
                .expect("valid URL");
        assert_eq!(canonical_query(&url), "a=hello%20world&z=last");
    }

    #[test]
    fn github_repository_is_validated() {
        let config = json!({"repository": "not-a-repository"});
        assert!(github_url(&config, "contents/a.json").is_err());
    }
}
