//! Built-in static site tarball publisher for pushes to a configured namespace
//! (e.g. `staticsites/<domain>` on `refs/heads/main`).
//!
//! Exports the pushed commit via `git archive --format=tar.gz`, uploads the
//! tarball to an S3-compatible bucket (e.g. Railway Storage Bucket `static.webforce`)
//! using AWS SigV4, and notifies `webforce-panel` via a bearer-authenticated webhook
//! so edge servers pull the release using short-lived read-only presigned URLs.

use std::env;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::process::Command;

type HmacSha256 = Hmac<Sha256>;

const MAX_ARCHIVE_BYTES: usize = 100 * 1024 * 1024; // 100 MiB safety cap

#[derive(Debug, Clone)]
pub struct StaticPublishConfig {
    pub namespace: String,
    pub branch: String,
    pub bucket: String,
    pub endpoint: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub webhook_url: Option<String>,
    pub webhook_token: Option<String>,
}

impl StaticPublishConfig {
    /// Load configuration from environment variables.
    /// Returns `None` if `WALGIT_STATIC_BUCKET` is unset or empty.
    pub fn from_env() -> Option<Self> {
        let bucket = env::var("WALGIT_STATIC_BUCKET")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        let endpoint = env::var("WALGIT_STATIC_ENDPOINT")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())?;
        let access_key_id = env::var("WALGIT_STATIC_ACCESS_KEY_ID")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        let secret_access_key = env::var("WALGIT_STATIC_SECRET_ACCESS_KEY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        let region = env::var("WALGIT_STATIC_REGION")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "auto".to_string());
        let namespace = env::var("WALGIT_STATIC_NAMESPACE")
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "staticsites".to_string());
        let branch = env::var("WALGIT_STATIC_BRANCH")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "refs/heads/main".to_string());
        let webhook_url = env::var("WALGIT_STATIC_WEBHOOK_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let webhook_token = env::var("WALGIT_STATIC_WEBHOOK_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        Some(Self {
            namespace,
            branch,
            bucket,
            endpoint,
            region,
            access_key_id,
            secret_access_key,
            webhook_url,
            webhook_token,
        })
    }
}

/// Validate a static site name (e.g. `feijoa.nz`, `www.example.com`, `my-site`).
pub fn is_valid_site_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    if name.starts_with('.') || name.ends_with('.') || name.contains("..") {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

#[derive(Debug, Serialize)]
struct PublishWebhookPayload {
    site: String,
    commit_sha: String,
    object_key: String,
    sha256: String,
    size_bytes: usize,
}

/// Called right after `publish_push_synced` succeeds.
/// Returns `Some(message)` for sideband narration if this repo matched the static namespace.
pub async fn maybe_publish_after_push(
    git_dir: &Path,
    owner: &str,
    repo_name: &str,
    pushed_refs: &[(String, String)], // (ref_name, new_oid)
    per_ref: &[(String, Result<(), String>)],
) -> Option<String> {
    let cfg = StaticPublishConfig::from_env()?;
    if !owner.eq_ignore_ascii_case(&cfg.namespace) {
        return None;
    }

    // Find whether the configured branch was updated and accepted
    let new_oid = pushed_refs
        .iter()
        .find(|(r, oid)| r == &cfg.branch && !oid.is_empty())
        .map(|(_, oid)| oid.as_str())?;

    let ref_ok = per_ref
        .iter()
        .find(|(r, _)| r == &cfg.branch)
        .map(|(_, res)| res.is_ok())
        .unwrap_or(false);
    if !ref_ok {
        return None;
    }

    let site = repo_name.trim().to_ascii_lowercase();
    if !is_valid_site_name(&site) {
        let msg = format!("static-publish: skipped invalid site name '{repo_name}'");
        tracing::warn!("{msg}");
        return Some(msg);
    }

    match publish_site_commit(&cfg, git_dir, &site, new_oid).await {
        Ok(msg) => {
            tracing::info!("{msg}");
            Some(msg)
        }
        Err(e) => {
            let msg = format!("static-publish: WARNING failed for {site}: {e:#}");
            tracing::error!("{msg}");
            Some(msg)
        }
    }
}

async fn publish_site_commit(
    cfg: &StaticPublishConfig,
    git_dir: &Path,
    site: &str,
    commit_sha: &str,
) -> Result<String> {
    // Export commit tree cleanly via `git archive --format=tar.gz`
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .arg("archive")
        .arg("--format=tar.gz")
        .arg(commit_sha)
        .output()
        .await
        .context("failed to spawn git archive")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("git archive failed: {}", stderr.trim()));
    }

    let tarball = output.stdout;
    if tarball.is_empty() {
        return Err(anyhow!("git archive produced empty tarball"));
    }
    if tarball.len() > MAX_ARCHIVE_BYTES {
        return Err(anyhow!(
            "static site archive ({} bytes) exceeds {} byte limit",
            tarball.len(),
            MAX_ARCHIVE_BYTES
        ));
    }

    let sha256_hex = hex::encode(Sha256::digest(&tarball));
    let short_sha = &commit_sha[..commit_sha.len().min(12)];
    let object_key = format!("{site}/{short_sha}.tar.gz");

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;

    s3_put_object(&client, cfg, &object_key, &tarball, &sha256_hex)
        .await
        .with_context(|| format!("S3 PUT failed for {object_key}"))?;

    let mut webhook_note = String::new();
    if let Some(webhook_url) = cfg.webhook_url.as_deref() {
        let payload = PublishWebhookPayload {
            site: site.to_string(),
            commit_sha: commit_sha.to_string(),
            object_key: object_key.clone(),
            sha256: sha256_hex.clone(),
            size_bytes: tarball.len(),
        };
        let mut req = client.post(webhook_url).json(&payload);
        if let Some(tok) = cfg.webhook_token.as_deref() {
            req = req.bearer_auth(tok);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("webhook POST to {webhook_url} failed"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "panel webhook returned HTTP {status}: {}",
                body.trim()
            ));
        }
        webhook_note = " -> edge sync triggered".to_string();
    }

    let kib = (tarball.len() as f64) / 1024.0;
    Ok(format!(
        "static-publish: uploaded {site} ({short_sha}, {kib:.1} KiB) to {}/{}{webhook_note}",
        cfg.bucket, object_key
    ))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sigv4_signing_key(secret: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

async fn s3_put_object(
    client: &Client,
    cfg: &StaticPublishConfig,
    object_key: &str,
    body: &[u8],
    payload_sha256: &str,
) -> Result<()> {
    let url = format!("{}/{}/{}", cfg.endpoint, cfg.bucket, object_key);
    let parsed = reqwest::Url::parse(&url).context("invalid S3 endpoint URL")?;
    let host = match parsed.port() {
        Some(p) => format!("{}:{p}", parsed.host_str().unwrap_or("")),
        None => parsed.host_str().unwrap_or("").to_string(),
    };
    let canonical_uri = parsed.path();

    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    let canonical_headers = format!(
        "content-type:application/gzip\nhost:{host}\nx-amz-content-sha256:{payload_sha256}\nx-amz-date:{amz_date}\n"
    );
    let signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "PUT\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_sha256}"
    );

    let credential_scope = format!("{date_stamp}/{}/s3/aws4_request", cfg.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let signing_key = sigv4_signing_key(&cfg.secret_access_key, &date_stamp, &cfg.region, "s3");
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        cfg.access_key_id
    );

    let resp = client
        .put(&url)
        .header("content-type", "application/gzip")
        .header("x-amz-content-sha256", payload_sha256)
        .header("x-amz-date", &amz_date)
        .header("authorization", &authorization)
        .body(body.to_vec())
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("S3 PUT returned HTTP {status}: {}", text.trim()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_site_name_validation() {
        assert!(is_valid_site_name("feijoa.nz"));
        assert!(is_valid_site_name("www.example.com"));
        assert!(is_valid_site_name("my-static-site"));
        assert!(!is_valid_site_name(""));
        assert!(!is_valid_site_name("../etc"));
        assert!(!is_valid_site_name("bad..site"));
        assert!(!is_valid_site_name("-bad.nz"));
        assert!(!is_valid_site_name("Upper.nz"));
    }

    #[test]
    fn test_sigv4_signing_key_deterministic() {
        let k1 = sigv4_signing_key("secret", "20261123", "auto", "s3");
        let k2 = sigv4_signing_key("secret", "20261123", "auto", "s3");
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
    }
}
