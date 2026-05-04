#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
DEFAULT_DB_PATH="${KIRO_CLI_DB:-$HOME/.local/share/kiro-cli/data.sqlite3}"

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME <output-path> [options]

Export Kiro CLI Social/BuilderId/IdC credentials from the local SQLite store to a
kiro-rs-compatible credentials.json file.

Arguments:
  <output-path>                 Destination path for credentials.json

Options:
  --db <path>                   Override the Kiro CLI SQLite database path
                                Default: $DEFAULT_DB_PATH
  --email <email>               Include an email field in the output JSON
  --profile-arn <arn>           Include profileArn in the output JSON
  --region <region>             Override region
  --auth-region <region>        Override authRegion
  --api-region <region>         Override apiRegion
  --auth-method <auto|social|idc>
                                Choose which Kiro CLI auth rows to export
                                Default: auto
  --omit-access-token           Do not write accessToken/expiresAt
  -h, --help                    Show this help message

Examples:
  $SCRIPT_NAME ./credentials.json
  $SCRIPT_NAME /etc/kiro/credentials.json --email you@example.com
  $SCRIPT_NAME ./credentials.json --db ~/.local/share/kiro-cli/data.sqlite3
EOF
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name" >&2
    exit 1
  fi
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '"%s"' "$value"
}

normalize_expires_at() {
  local raw="${1:-}"

  if [[ -z "$raw" ]]; then
    return 0
  fi

  if [[ "$raw" =~ ^[0-9]{13}$ ]]; then
    date -u -d "@$((raw / 1000))" '+%Y-%m-%dT%H:%M:%SZ'
    return 0
  fi

  if [[ "$raw" =~ ^[0-9]{10}$ ]]; then
    date -u -d "@$raw" '+%Y-%m-%dT%H:%M:%SZ'
    return 0
  fi

  if [[ "$raw" =~ ^[0-9]+$ ]]; then
    date -u -d "@$raw" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null && return 0
  fi

  if [[ "$raw" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]]; then
    printf '%s\n' "$raw"
    return 0
  fi

  date -u -d "$raw" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf '%s\n' "$raw"
}

sql_value() {
  local sql="$1"
  sqlite3 -tabs -noheader "$DB_PATH" "$sql"
}

OUTPUT_PATH=""
DB_PATH="$DEFAULT_DB_PATH"
EMAIL=""
PROFILE_ARN=""
REGION_OVERRIDE=""
AUTH_REGION_OVERRIDE=""
API_REGION_OVERRIDE=""
AUTH_METHOD_OVERRIDE="auto"
OMIT_ACCESS_TOKEN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --db)
      DB_PATH="${2:-}"
      shift 2
      ;;
    --email)
      EMAIL="${2:-}"
      shift 2
      ;;
    --profile-arn)
      PROFILE_ARN="${2:-}"
      shift 2
      ;;
    --region)
      REGION_OVERRIDE="${2:-}"
      shift 2
      ;;
    --auth-region)
      AUTH_REGION_OVERRIDE="${2:-}"
      shift 2
      ;;
    --api-region)
      API_REGION_OVERRIDE="${2:-}"
      shift 2
      ;;
    --auth-method)
      AUTH_METHOD_OVERRIDE="${2:-}"
      shift 2
      ;;
    --omit-access-token)
      OMIT_ACCESS_TOKEN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      if [[ -n "$OUTPUT_PATH" ]]; then
        echo "Only one output path may be provided." >&2
        usage >&2
        exit 1
      fi
      OUTPUT_PATH="$1"
      shift
      ;;
  esac
done

if [[ -z "$OUTPUT_PATH" ]]; then
  usage >&2
  exit 1
fi

require_command sqlite3
require_command date

if [[ ! -f "$DB_PATH" ]]; then
  echo "Kiro CLI database not found: $DB_PATH" >&2
  exit 1
fi

case "${AUTH_METHOD_OVERRIDE,,}" in
  auto|social|idc)
    AUTH_METHOD_OVERRIDE="${AUTH_METHOD_OVERRIDE,,}"
    ;;
  builder-id|iam)
    AUTH_METHOD_OVERRIDE="idc"
    ;;
  *)
    echo "Unsupported auth method: $AUTH_METHOD_OVERRIDE" >&2
    usage >&2
    exit 1
    ;;
esac

has_idc_token="$(sql_value "SELECT 1 FROM auth_kv WHERE key IN ('kirocli:odic:token', 'kirocli:oidc:token') LIMIT 1;")"
has_idc_device="$(sql_value "SELECT 1 FROM auth_kv WHERE key IN ('kirocli:odic:device-registration', 'kirocli:oidc:device-registration') LIMIT 1;")"
has_social_token="$(sql_value "SELECT 1 FROM auth_kv WHERE key = 'kirocli:social:token' LIMIT 1;")"

AUTH_METHOD=""
case "$AUTH_METHOD_OVERRIDE" in
  auto)
    if [[ -n "$has_idc_token" && -n "$has_idc_device" ]]; then
      AUTH_METHOD="idc"
    elif [[ -n "$has_social_token" ]]; then
      AUTH_METHOD="social"
    elif [[ -n "$has_idc_token" || -n "$has_idc_device" ]]; then
      echo "Incomplete Kiro CLI IdC auth rows were found in $DB_PATH" >&2
      exit 1
    else
      echo "No Kiro CLI auth rows were found in $DB_PATH" >&2
      exit 1
    fi
    ;;
  idc)
    if [[ -z "$has_idc_token" && -z "$has_idc_device" ]]; then
      echo "No Kiro CLI IdC auth rows were found in $DB_PATH" >&2
      exit 1
    fi
    if [[ -z "$has_idc_token" || -z "$has_idc_device" ]]; then
      echo "Incomplete Kiro CLI IdC auth rows were found in $DB_PATH" >&2
      exit 1
    fi
    AUTH_METHOD="idc"
    ;;
  social)
    if [[ -z "$has_social_token" ]]; then
      echo "No Kiro CLI Social auth rows were found in $DB_PATH" >&2
      exit 1
    fi
    AUTH_METHOD="social"
    ;;
esac

if [[ "$AUTH_METHOD" == "idc" ]]; then
  read_query="$(cat <<'SQL'
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
  COALESCE(json_extract(t.value, '$.access_token'), ''),
  COALESCE(json_extract(t.value, '$.refresh_token'), ''),
  COALESCE(json_extract(t.value, '$.expires_at'), ''),
  COALESCE(json_extract(t.value, '$.region'), json_extract(d.value, '$.region'), ''),
  COALESCE(json_extract(d.value, '$.client_id'), ''),
  COALESCE(json_extract(d.value, '$.client_secret'), '')
FROM token_row t
CROSS JOIN device_row d;
SQL
)"
else
  read_query="$(cat <<'SQL'
SELECT
  COALESCE(json_extract(value, '$.access_token'), ''),
  COALESCE(json_extract(value, '$.refresh_token'), ''),
  COALESCE(json_extract(value, '$.expires_at'), ''),
  COALESCE(json_extract(value, '$.region'), ''),
  '',
  ''
FROM auth_kv
WHERE key = 'kirocli:social:token'
LIMIT 1;
SQL
)"
fi

row="$(sql_value "$read_query")"
if [[ -z "$row" ]]; then
  echo "No Kiro CLI $AUTH_METHOD auth rows could be exported from $DB_PATH" >&2
  exit 1
fi

IFS=$'\t' read -r ACCESS_TOKEN REFRESH_TOKEN EXPIRES_RAW DETECTED_REGION CLIENT_ID CLIENT_SECRET <<<"$row"

if [[ -z "$REFRESH_TOKEN" ]]; then
  echo "refresh_token is missing from the Kiro CLI database." >&2
  exit 1
fi

if [[ "$AUTH_METHOD" == "idc" && ( -z "$CLIENT_ID" || -z "$CLIENT_SECRET" ) ]]; then
  echo "client_id/client_secret are missing from the Kiro CLI database." >&2
  exit 1
fi

REGION="${REGION_OVERRIDE:-$DETECTED_REGION}"
AUTH_REGION="${AUTH_REGION_OVERRIDE:-$REGION}"
API_REGION="${API_REGION_OVERRIDE:-$REGION}"
EXPIRES_AT=""

if [[ "$OMIT_ACCESS_TOKEN" -eq 0 && -n "$EXPIRES_RAW" ]]; then
  EXPIRES_AT="$(normalize_expires_at "$EXPIRES_RAW")"
fi

json_lines=()
append_field() {
  local key="$1"
  local value="${2:-}"
  if [[ -n "$value" ]]; then
    json_lines+=("  $(json_escape "$key"): $(json_escape "$value")")
  fi
}

if [[ "$OMIT_ACCESS_TOKEN" -eq 0 ]]; then
  append_field "accessToken" "$ACCESS_TOKEN"
fi
append_field "refreshToken" "$REFRESH_TOKEN"
append_field "profileArn" "$PROFILE_ARN"
append_field "expiresAt" "$EXPIRES_AT"
append_field "authMethod" "$AUTH_METHOD"
append_field "clientId" "$CLIENT_ID"
append_field "clientSecret" "$CLIENT_SECRET"
append_field "region" "$REGION"
append_field "authRegion" "$AUTH_REGION"
append_field "apiRegion" "$API_REGION"
append_field "email" "$EMAIL"

if [[ "${#json_lines[@]}" -eq 0 ]]; then
  echo "No credentials could be exported." >&2
  exit 1
fi

target_dir="$(dirname "$OUTPUT_PATH")"
mkdir -p "$target_dir"
umask 077
tmp_file="$(mktemp "$target_dir/.credentials.json.tmp.XXXXXX")"
trap 'rm -f "$tmp_file"' EXIT

{
  printf '{\n'
  for i in "${!json_lines[@]}"; do
    if [[ "$i" -gt 0 ]]; then
      printf ',\n'
    fi
    printf '%s' "${json_lines[$i]}"
  done
  printf '\n}\n'
} >"$tmp_file"

mv "$tmp_file" "$OUTPUT_PATH"
trap - EXIT

echo "credentials.json written to: $OUTPUT_PATH"
