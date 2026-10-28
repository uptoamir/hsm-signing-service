#!/usr/bin/env bash
# Creates (once) a local SoftHSM2 token for development and prints the
# environment variables the service needs. PINs are generated randomly and
# written to files with mode 0600; nothing is hard-coded.
#
#   eval "$(./scripts/dev-token.sh)"
#   cargo run --release -- serve
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${SOFTHSM_DIR:-$ROOT/.softhsm}"
LABEL="${HSM_TOKEN_LABEL:-arkion}"

command -v softhsm2-util >/dev/null || { echo "softhsm2-util not found (brew install softhsm / apt install softhsm2)" >&2; exit 1; }

mkdir -p "$DIR/tokens"
CONF="$DIR/softhsm2.conf"
cat > "$CONF" <<CONF_EOF
directories.tokendir = $DIR/tokens
objectstore.backend = file
log.level = ERROR
CONF_EOF
export SOFTHSM2_CONF="$CONF"

if softhsm2-util --show-slots 2>/dev/null | grep -E '^[[:space:]]+Label:' | grep -qw -- "$LABEL"; then
  echo "# token '$LABEL' already exists in $DIR" >&2
else
  SO_PIN="${HSM_SO_PIN:-$(openssl rand -hex 8)}"
  USER_PIN="${HSM_USER_PIN:-$(openssl rand -hex 8)}"
  umask 077
  printf '%s' "$USER_PIN" > "$DIR/user_pin.txt"
  printf '%s' "$SO_PIN" > "$DIR/so_pin.txt"
  softhsm2-util --init-token --free --label "$LABEL" --so-pin "$SO_PIN" --pin "$USER_PIN" >/dev/null
  echo "# initialized token '$LABEL' in $DIR; PINs stored in $DIR/{user_pin,so_pin}.txt (mode 0600)" >&2
fi

case "$(uname -s)" in
  Darwin) MODULE="${PKCS11_MODULE:-/opt/homebrew/lib/softhsm/libsofthsm2.so}" ;;
  *)      MODULE="${PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}" ;;
esac

cat <<ENV_EOF
export SOFTHSM2_CONF="$CONF"
export PKCS11_MODULE="$MODULE"
export HSM_TOKEN_LABEL="$LABEL"
export HSM_USER_PIN_FILE="$DIR/user_pin.txt"
ENV_EOF
cat > "$DIR/env.sh" <<ENV_EOF
export SOFTHSM2_CONF="$CONF"
export PKCS11_MODULE="$MODULE"
export HSM_TOKEN_LABEL="$LABEL"
export HSM_USER_PIN_FILE="$DIR/user_pin.txt"
ENV_EOF
