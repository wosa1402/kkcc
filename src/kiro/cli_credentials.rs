//! Local Kiro CLI credential discovery.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};

use crate::kiro::model::credentials::KiroCredentials;

const KIRO_CLI_DB_ENV: &str = "KIRO_CLI_DB";
const DEFAULT_KIRO_CLI_DB: &str = ".local/share/kiro-cli/data.sqlite3";

pub struct DetectedCredentials {
    pub credentials: KiroCredentials,
    pub db_path: PathBuf,
}

struct ExportRow {
    access_token: String,
    refresh_token: String,
    expires_raw: String,
    region: String,
    client_id: String,
    client_secret: String,
}

pub fn detect_local_credentials() -> anyhow::Result<Option<DetectedCredentials>> {
    detect_local_credentials_from(None)
}

pub fn detect_local_credentials_from(
    db_override: Option<PathBuf>,
) -> anyhow::Result<Option<DetectedCredentials>> {
    let Some(db_path) = default_db_path(db_override) else {
        return Ok(None);
    };

    if !db_path.is_file() {
        return Ok(None);
    }

    let Some(credentials) = load_from_db(&db_path)? else {
        return Ok(None);
    };

    Ok(Some(DetectedCredentials {
        credentials,
        db_path,
    }))
}

fn default_db_path(db_override: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(path) = db_override {
        return Some(path);
    }

    if let Some(path) = std::env::var_os(KIRO_CLI_DB_ENV) {
        return Some(PathBuf::from(path));
    }

    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|home| PathBuf::from(home).join(DEFAULT_KIRO_CLI_DB))
}

fn load_from_db(db_path: &Path) -> anyhow::Result<Option<KiroCredentials>> {
    let has_idc_token = has_row(
        db_path,
        "SELECT 1 FROM auth_kv WHERE key IN ('kirocli:odic:token', 'kirocli:oidc:token') LIMIT 1;",
    )?;
    let has_idc_device = has_row(
        db_path,
        "SELECT 1 FROM auth_kv WHERE key IN ('kirocli:odic:device-registration', 'kirocli:oidc:device-registration') LIMIT 1;",
    )?;
    let has_social_token = has_row(
        db_path,
        "SELECT 1 FROM auth_kv WHERE key = 'kirocli:social:token' LIMIT 1;",
    )?;

    if has_idc_token && has_idc_device {
        let row = query_export_row(db_path, IDC_EXPORT_QUERY)?;
        return Ok(Some(build_credentials("idc", row)?));
    }

    if has_social_token {
        let row = query_export_row(db_path, SOCIAL_EXPORT_QUERY)?;
        return Ok(Some(build_credentials("social", row)?));
    }

    if has_idc_token || has_idc_device {
        bail!("incomplete Kiro CLI IdC auth rows were found in {}", db_path.display());
    }

    Ok(None)
}

fn has_row(db_path: &Path, sql: &str) -> anyhow::Result<bool> {
    Ok(!sqlite_value(db_path, sql)?.trim().is_empty())
}

fn query_export_row(db_path: &Path, sql: &str) -> anyhow::Result<ExportRow> {
    let output = sqlite_value(db_path, sql)?;
    let row = output.trim_end_matches(|c| c == '\r' || c == '\n');
    if row.is_empty() {
        bail!("no Kiro CLI auth rows could be exported from {}", db_path.display());
    }

    let mut fields = row.split('\t');
    let export_row = ExportRow {
        access_token: fields.next().unwrap_or_default().to_string(),
        refresh_token: fields.next().unwrap_or_default().to_string(),
        expires_raw: fields.next().unwrap_or_default().to_string(),
        region: fields.next().unwrap_or_default().to_string(),
        client_id: fields.next().unwrap_or_default().to_string(),
        client_secret: fields.next().unwrap_or_default().to_string(),
    };

    Ok(export_row)
}

fn sqlite_value(db_path: &Path, sql: &str) -> anyhow::Result<String> {
    let output = Command::new("sqlite3")
        .arg("-tabs")
        .arg("-noheader")
        .arg(db_path)
        .arg(sql)
        .output()
        .with_context(|| {
            "failed to run sqlite3 while auto-detecting Kiro CLI credentials; \
             install sqlite3 or provide credentials.json explicitly"
        })?;

    if !output.status.success() {
        bail!(
            "sqlite3 failed while reading {}: {}",
            db_path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    String::from_utf8(output.stdout).context("sqlite3 returned non-UTF-8 output")
}

fn build_credentials(auth_method: &str, row: ExportRow) -> anyhow::Result<KiroCredentials> {
    if row.refresh_token.trim().is_empty() {
        bail!("refresh_token is missing from the Kiro CLI database");
    }

    if auth_method == "idc"
        && (row.client_id.trim().is_empty() || row.client_secret.trim().is_empty())
    {
        bail!("client_id/client_secret are missing from the Kiro CLI database");
    }

    let region = non_empty(row.region);

    Ok(KiroCredentials {
        access_token: non_empty(row.access_token),
        refresh_token: Some(row.refresh_token),
        expires_at: normalize_expires_at(&row.expires_raw),
        auth_method: Some(auth_method.to_string()),
        client_id: non_empty(row.client_id),
        client_secret: non_empty(row.client_secret),
        region: region.clone(),
        auth_region: region.clone(),
        api_region: region,
        ..Default::default()
    })
}

fn non_empty(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_expires_at(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    if raw.chars().all(|c| c.is_ascii_digit()) {
        let Ok(value) = raw.parse::<i64>() else {
            return Some(raw.to_string());
        };
        let seconds = if raw.len() == 13 { value / 1000 } else { value };
        return DateTime::<Utc>::from_timestamp(seconds, 0).map(|dt| dt.to_rfc3339());
    }

    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc).to_rfc3339());
    }

    Some(raw.to_string())
}

const IDC_EXPORT_QUERY: &str = r#"
WITH token_row AS (
  SELECT value
  FROM auth_kv
  WHERE key IN ('kirocli:odic:token', 'kirocli:oidc:token')
  ORDER BY CASE key
    WHEN 'kirocli:odic:token' THEN 0
    ELSE 1
  END
  LIMIT 1
),
device_row AS (
  SELECT value
  FROM auth_kv
  WHERE key IN ('kirocli:odic:device-registration', 'kirocli:oidc:device-registration')
  ORDER BY CASE key
    WHEN 'kirocli:odic:device-registration' THEN 0
    ELSE 1
  END
  LIMIT 1
)
SELECT
  COALESCE(json_extract(t.value, '$.access_token'), json_extract(t.value, '$.accessToken'), json_extract(t.value, '$.poll_response.accessToken'), ''),
  COALESCE(json_extract(t.value, '$.refresh_token'), json_extract(t.value, '$.refreshToken'), json_extract(t.value, '$.poll_response.refreshToken'), ''),
  COALESCE(json_extract(t.value, '$.expires_at'), json_extract(t.value, '$.expiresAt'), ''),
  COALESCE(json_extract(t.value, '$.region'), json_extract(d.value, '$.region'), ''),
  COALESCE(json_extract(d.value, '$.client_id'), json_extract(d.value, '$.clientId'), json_extract(t.value, '$.client_id'), json_extract(t.value, '$.clientId'), ''),
  COALESCE(json_extract(d.value, '$.client_secret'), json_extract(d.value, '$.clientSecret'), json_extract(t.value, '$.client_secret'), json_extract(t.value, '$.clientSecret'), '')
FROM token_row t
CROSS JOIN device_row d;
"#;

const SOCIAL_EXPORT_QUERY: &str = r#"
SELECT
  COALESCE(json_extract(value, '$.access_token'), json_extract(value, '$.accessToken'), json_extract(value, '$.poll_response.accessToken'), ''),
  COALESCE(json_extract(value, '$.refresh_token'), json_extract(value, '$.refreshToken'), json_extract(value, '$.poll_response.refreshToken'), ''),
  COALESCE(json_extract(value, '$.expires_at'), json_extract(value, '$.expiresAt'), ''),
  COALESCE(json_extract(value, '$.region'), ''),
  '',
  ''
FROM auth_kv
WHERE key = 'kirocli:social:token'
LIMIT 1;
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_epoch_millis() {
        assert_eq!(
            normalize_expires_at("1700000000000"),
            Some("2023-11-14T22:13:20+00:00".to_string())
        );
    }

    #[test]
    fn builds_idc_credentials() {
        let row = ExportRow {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            expires_raw: "2025-01-01T00:00:00Z".to_string(),
            region: "us-east-1".to_string(),
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
        };

        let credentials = build_credentials("idc", row).unwrap();

        assert_eq!(credentials.auth_method.as_deref(), Some("idc"));
        assert_eq!(credentials.refresh_token.as_deref(), Some("refresh"));
        assert_eq!(credentials.client_id.as_deref(), Some("client"));
        assert_eq!(credentials.client_secret.as_deref(), Some("secret"));
        assert_eq!(credentials.region.as_deref(), Some("us-east-1"));
        assert_eq!(credentials.auth_region.as_deref(), Some("us-east-1"));
        assert_eq!(credentials.api_region.as_deref(), Some("us-east-1"));
    }
}
