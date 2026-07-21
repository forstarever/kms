#!/usr/bin/env bash
set -euo pipefail

KMS_REPO="${KMS_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SOFTHSM_PROJECT="${SOFTHSM_PROJECT:-$(cd "$KMS_REPO/../SoftHSMv2_cuda" && pwd)}"

export SOFTHSM2_CONF="${SOFTHSM2_CONF:-$SOFTHSM_PROJECT/softhsm2.conf}"
export SOFTHSM2_PKCS11_LIB="${SOFTHSM2_PKCS11_LIB:-$SOFTHSM_PROJECT/src/lib/.libs/libsofthsm2.so}"

SOFTHSM2_UTIL="${SOFTHSM2_UTIL:-$SOFTHSM_PROJECT/src/bin/util/softhsm2-util}"
LOCAL_SOFTHSM_PIN="${LOCAL_SOFTHSM_PIN:-12345678}"
LOCAL_SOFTHSM_SO_PIN="${LOCAL_SOFTHSM_SO_PIN:-12345678}"
LOCAL_SOFTHSM_LABEL="${LOCAL_SOFTHSM_LABEL:-kms-local}"

KMS_HOST="${KMS_HOST:-0.0.0.0}"
KMS_PORT="${KMS_PORT:-9998}"
KMS_SQLITE_PATH="${KMS_SQLITE_PATH:-$KMS_REPO/data/local-softhsm-sqlite}"
KMS_LOCAL_CONF="${KMS_LOCAL_CONF:-$KMS_REPO/data/local-softhsm-kms.toml}"
CARGO_BIN="${CARGO_BIN:-cargo}"

if ! command -v "$CARGO_BIN" >/dev/null 2>&1; then
  if [[ -x /home/star/.cargo/bin/cargo ]]; then
    CARGO_BIN=/home/star/.cargo/bin/cargo
  else
    echo "Missing cargo. Set CARGO_BIN or add cargo to PATH." >&2
    exit 1
  fi
fi

require_file() {
  local path="$1"
  local label="$2"
  if [[ ! -e "$path" ]]; then
    echo "Missing $label: $path" >&2
    exit 1
  fi
}

detect_initialized_slot() {
  "$SOFTHSM2_UTIL" --show-slots | awk '
    /^Slot / { slot = $2 }
    /Initialized:[[:space:]]+yes/ { print slot; exit }
  '
}

detect_slot_by_label() {
  "$SOFTHSM2_UTIL" --show-slots | awk -v wanted="$LOCAL_SOFTHSM_LABEL" '
    /^Slot / {
      slot = $2
      initialized = 0
    }
    /Initialized:[[:space:]]+yes/ {
      initialized = 1
    }
    /Label:/ {
      label = $0
      sub(/^.*Label:[[:space:]]*/, "", label)
      gsub(/[[:space:]]+$/, "", label)
      if (initialized && label == wanted) {
        print slot
        exit
      }
    }
  '
}

require_file "$SOFTHSM2_CONF" "SoftHSM2 config"
require_file "$SOFTHSM2_PKCS11_LIB" "SoftHSM2 PKCS#11 library"
require_file "$SOFTHSM2_UTIL" "softhsm2-util"

token_dir="$(
  awk -F= '/^[[:space:]]*directories\.tokendir[[:space:]]*=/{ gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit }' "$SOFTHSM2_CONF"
)"
if [[ -n "$token_dir" ]]; then
  mkdir -p "$token_dir"
fi

slot_id="$(detect_slot_by_label)"
if [[ -z "$slot_id" ]]; then
  "$SOFTHSM2_UTIL" --init-token --free \
    --label "$LOCAL_SOFTHSM_LABEL" \
    --so-pin "$LOCAL_SOFTHSM_SO_PIN" \
    --pin "$LOCAL_SOFTHSM_PIN"
  slot_id="$(detect_slot_by_label)"
fi

if [[ -z "$slot_id" ]]; then
  echo "Unable to find or initialize SoftHSM2 token '$LOCAL_SOFTHSM_LABEL' in $SOFTHSM2_CONF" >&2
  echo "Existing initialized slots:" >&2
  detect_initialized_slot >&2 || true
  exit 1
fi

mkdir -p "$(dirname "$KMS_LOCAL_CONF")" "$KMS_SQLITE_PATH"
umask 077
cat > "$KMS_LOCAL_CONF" <<EOF
default_username = "admin"

[[hsm_instances]]
hsm_model = "softhsm2"
hsm_admin = ["admin"]
hsm_slot = [$slot_id]
hsm_password = ["$LOCAL_SOFTHSM_PIN"]

[http]
port = $KMS_PORT
hostname = "$KMS_HOST"

[db]
database_type = "sqlite"
sqlite_path = "$KMS_SQLITE_PATH"
clear_database = false
unwrapped_cache_max_age = 15
EOF

export COSMIAN_KMS_CONF="$KMS_LOCAL_CONF"

echo "Using SoftHSM2 library: $SOFTHSM2_PKCS11_LIB"
echo "Using SoftHSM2 config:  $SOFTHSM2_CONF"
echo "Using SoftHSM2 slot:    $slot_id"
echo "Using KMS config:       $COSMIAN_KMS_CONF"
echo "KMS URL:                http://$KMS_HOST:$KMS_PORT"

if [[ "${KMS_PRINT_CONFIG_ONLY:-0}" == "1" ]]; then
  exit 0
fi

cd "$KMS_REPO"
exec "$CARGO_BIN" run --bin cosmian_kms --features non-fips -- "$@"
