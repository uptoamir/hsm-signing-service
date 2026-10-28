#!/usr/bin/env bash
# Container entrypoint: makes sure a SoftHSM2 token exists, then execs the
# service. The user PIN is taken from HSM_USER_PIN_FILE (Docker/Kubernetes
# secret), else HSM_USER_PIN, else -- for throw-away dev containers only --
# generated at random and stored next to the token with mode 0600.
set -euo pipefail

: "${HSM_TOKEN_LABEL:=arkion}"
: "${SOFTHSM2_CONF:=/etc/hsm-signer/softhsm2.conf}"
export HSM_TOKEN_LABEL SOFTHSM2_CONF

read_secret() {
  # $1 = name of the *_FILE variable, $2 = name of the plain variable
  local file_var="$1" plain_var="$2"
  if [[ -n "${!file_var:-}" ]]; then
    tr -d '\r\n' < "${!file_var}"
  elif [[ -n "${!plain_var:-}" ]]; then
    printf '%s' "${!plain_var}"
  fi
}

USER_PIN="$(read_secret HSM_USER_PIN_FILE HSM_USER_PIN)"
SO_PIN="$(read_secret HSM_SO_PIN_FILE HSM_SO_PIN)"
TOKEN_DIR="$(awk -F= '/^directories.tokendir/ {gsub(/[[:space:]]/, "", $2); print $2}' "$SOFTHSM2_CONF")"
mkdir -p "$TOKEN_DIR"
GENERATED_PIN_FILE="$TOKEN_DIR/.user_pin"

if ! softhsm2-util --show-slots 2>/dev/null | grep -E '^[[:space:]]+Label:' | grep -qw -- "$HSM_TOKEN_LABEL"; then
  if [[ -z "$USER_PIN" ]]; then
    USER_PIN="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    (umask 077; printf '%s' "$USER_PIN" > "$GENERATED_PIN_FILE")
    echo "entrypoint: no user PIN supplied; generated one and stored it at $GENERATED_PIN_FILE (dev mode)" >&2
  fi
  if [[ -z "$SO_PIN" ]]; then
    SO_PIN="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi
  softhsm2-util --init-token --free --label "$HSM_TOKEN_LABEL" --so-pin "$SO_PIN" --pin "$USER_PIN" >/dev/null
  echo "entrypoint: initialized SoftHSM2 token '$HSM_TOKEN_LABEL'" >&2
fi

if [[ -z "$USER_PIN" && -f "$GENERATED_PIN_FILE" ]]; then
  export HSM_USER_PIN_FILE="$GENERATED_PIN_FILE"
elif [[ -z "${HSM_USER_PIN_FILE:-}" && -n "$USER_PIN" && -z "${HSM_USER_PIN:-}" ]]; then
  : # PIN came from a file already exported as HSM_USER_PIN_FILE
fi

# The service never needs the SO PIN; do not leave it in its environment.
unset HSM_SO_PIN HSM_SO_PIN_FILE SO_PIN USER_PIN

exec "$@"
