#!/usr/bin/env bash
set -euo pipefail

AUTO_INSTALL="${AUTO_INSTALL:-1}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"
MAX_TIME="${MAX_TIME:-15}"
CURL_OPTS=(-sS --connect-timeout "${CONNECT_TIMEOUT}" --max-time "${MAX_TIME}")

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_pkg() {
  local status=1
  local sudo_cmd=""
  if have_cmd sudo; then
    sudo_cmd="sudo"
  fi

  set +e
  if have_cmd apt-get; then
    $sudo_cmd apt-get update -y >/dev/null 2>&1
    for pkg in "$@"; do
      $sudo_cmd apt-get install -y "$pkg" >/dev/null 2>&1
      if [[ $? -eq 0 ]]; then
        status=0
        break
      fi
    done
  elif have_cmd dnf; then
    for pkg in "$@"; do
      $sudo_cmd dnf install -y "$pkg" >/dev/null 2>&1
      if [[ $? -eq 0 ]]; then
        status=0
        break
      fi
    done
  elif have_cmd yum; then
    for pkg in "$@"; do
      $sudo_cmd yum install -y "$pkg" >/dev/null 2>&1
      if [[ $? -eq 0 ]]; then
        status=0
        break
      fi
    done
  elif have_cmd apk; then
    for pkg in "$@"; do
      $sudo_cmd apk add --no-cache "$pkg" >/dev/null 2>&1
      if [[ $? -eq 0 ]]; then
        status=0
        break
      fi
    done
  elif have_cmd pacman; then
    for pkg in "$@"; do
      $sudo_cmd pacman -Sy --noconfirm "$pkg" >/dev/null 2>&1
      if [[ $? -eq 0 ]]; then
        status=0
        break
      fi
    done
  elif have_cmd zypper; then
    for pkg in "$@"; do
      $sudo_cmd zypper --non-interactive install "$pkg" >/dev/null 2>&1
      if [[ $? -eq 0 ]]; then
        status=0
        break
      fi
    done
  elif have_cmd brew; then
    for pkg in "$@"; do
      brew install "$pkg" >/dev/null 2>&1
      if [[ $? -eq 0 ]]; then
        status=0
        break
      fi
    done
  elif have_cmd choco; then
    for pkg in "$@"; do
      cmd.exe /c choco install -y "$pkg" >/dev/null 2>&1
      if [[ $? -eq 0 ]]; then
        status=0
        break
      fi
    done
  fi
  set -e

  return $status
}

ensure_cmd() {
  local cmd="$1"
  shift
  if have_cmd "$cmd"; then
    return 0
  fi
  if [[ "${AUTO_INSTALL}" != "1" ]]; then
    echo "Missing command: ${cmd} (set AUTO_INSTALL=1 to auto-install)" >&2
    return 1
  fi
  if ! install_pkg "$@"; then
    echo "Failed to install: ${cmd}" >&2
    return 1
  fi
  have_cmd "$cmd"
}

if ! ensure_cmd curl curl; then
  echo "curl is required to run this script." >&2
  exit 1
fi

BASE_URL="${BASE_URL:-http://httpbin.org}"

# Simple query string with email/phone/token
curl "${CURL_OPTS[@]}" "${BASE_URL}/get?email=john.doe%40example.com&phone=+1-415-555-0101&token=abc123xyz789" -o /dev/null

# JSON body with PII-like fields
curl "${CURL_OPTS[@]}" -X POST "${BASE_URL}/post" \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice Nguyen","email":"alice.nguyen@example.com","ssn":"123-45-6789","address":"21 Jump Street","api_key":"AKIA_TEST_123456"}' \
  -o /dev/null

# Form-urlencoded credentials
curl "${CURL_OPTS[@]}" -X POST "${BASE_URL}/post" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=Sup3rSecr3t!&otp=123456" \
  -o /dev/null

# Basic auth header
curl "${CURL_OPTS[@]}" -u "bob:password123" "${BASE_URL}/basic-auth/bob/password123" -o /dev/null

# Bearer token header
curl "${CURL_OPTS[@]}" "${BASE_URL}/bearer" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.TEST_PAYLOAD.SIGN" \
  -o /dev/null

# Multipart form-data with secrets
curl "${CURL_OPTS[@]}" -X POST "${BASE_URL}/post" \
  -F "email=carol@example.com" \
  -F "password=Passw0rd!" \
  -F "note=My token is tok_123456789" \
  -o /dev/null

# URL-encoded payload content
curl "${CURL_OPTS[@]}" -X POST "${BASE_URL}/post" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comment=ssn%3D111-22-3333%26phone%3D%2B1-202-555-0198" \
  -o /dev/null

# Credit card + IBAN + IP in query
curl "${CURL_OPTS[@]}" "${BASE_URL}/get?cc=4111111111111111&iban=GB82WEST12345698765432&ip=203.0.113.10" -o /dev/null

# JSON with JWT/session/id
curl "${CURL_OPTS[@]}" -X POST "${BASE_URL}/post" \
  -H "Content-Type: application/json" \
  -d '{"session_id":"sess_9f8e7d6c5b4a","jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdGVyIn0.SIGN","refresh_token":"r1_AbCdEfGhIjKlMnOp"}' \
  -o /dev/null

# API key in header + cookie token
curl "${CURL_OPTS[@]}" "${BASE_URL}/get" \
  -H "X-API-Key: TEST_API_KEY_ABC123XYZ" \
  -H "Cookie: session=SESS_ABC123; token=tok_987654321" \
  -o /dev/null

# Multipart with phone and address
curl "${CURL_OPTS[@]}" -X POST "${BASE_URL}/post" \
  -F "phone=+1-650-555-0100" \
  -F "address=742 Evergreen Terrace" \
  -F "note=verification_code: 654321" \
  -o /dev/null

# FTP (non-HTTP) - anonymous download (clear-text control channel)
FTP_URL="ftp://test.rebex.net"
FTP_USER="${FTP_USER:-anonymous}"
FTP_PASS="${FTP_PASS:-anonymous@example.com}"
FTP_PATH="${FTP_PATH:-/gnu/README}"
curl "${CURL_OPTS[@]}" --user "${FTP_USER}:${FTP_PASS}" "${FTP_URL}${FTP_PATH}" -o /dev/null || true

# SMB (non-HTTP) - optional; set SMB_TARGET like //server/share (public SMB is rare)
if [[ -n "${SMB_TARGET:-}" ]]; then
  ensure_cmd smbclient smbclient samba-client samba || true
fi
if command -v smbclient >/dev/null 2>&1 && [[ -n "${SMB_TARGET:-}" ]]; then
  SMB_USER="${SMB_USER:-guest}"
  SMB_PASS="${SMB_PASS:-}" 
  smbclient "${SMB_TARGET}" -U "${SMB_USER}%${SMB_PASS}" -c "ls" >/dev/null 2>&1 || true
fi

# SMTP (non-HTTP) - optional; set SMTP_HOST (public plaintext SMTP is rare)
if [[ -n "${SMTP_HOST:-}" ]]; then
  ensure_cmd nc netcat-openbsd nmap-ncat netcat ncat || true
fi
if command -v nc >/dev/null 2>&1 && [[ -n "${SMTP_HOST:-}" ]]; then
  SMTP_PORT="${SMTP_PORT:-25}"
  printf 'EHLO test\r\nMAIL FROM:<alice@example.com>\r\nRCPT TO:<bob@example.com>\r\nDATA\r\nSubject: leak-test\r\n\r\npassword=Sup3rSecr3t! otp=654321\r\n.\r\nQUIT\r\n' \
    | nc -w 3 "${SMTP_HOST}" "${SMTP_PORT}" >/dev/null 2>&1 || true
fi

# POP3 (non-HTTP) - optional; set POP3_HOST (public plaintext POP3 is rare)
if [[ -n "${POP3_HOST:-}" ]]; then
  ensure_cmd nc netcat-openbsd nmap-ncat netcat ncat || true
fi
if command -v nc >/dev/null 2>&1 && [[ -n "${POP3_HOST:-}" ]]; then
  POP3_PORT="${POP3_PORT:-110}"
  printf 'USER tester\r\nPASS Passw0rd!\r\nQUIT\r\n' \
    | nc -w 3 "${POP3_HOST}" "${POP3_PORT}" >/dev/null 2>&1 || true
fi

# IMAP (non-HTTP) - optional; set IMAP_HOST (public plaintext IMAP is rare)
if [[ -n "${IMAP_HOST:-}" ]]; then
  ensure_cmd nc netcat-openbsd nmap-ncat netcat ncat || true
fi
if command -v nc >/dev/null 2>&1 && [[ -n "${IMAP_HOST:-}" ]]; then
  IMAP_PORT="${IMAP_PORT:-143}"
  printf 'a1 LOGIN tester Passw0rd!\r\na2 LOGOUT\r\n' \
    | nc -w 3 "${IMAP_HOST}" "${IMAP_PORT}" >/dev/null 2>&1 || true
fi

# MQTT (non-HTTP) - public broker
MQTT_HOST="${MQTT_HOST:-test.mosquitto.org}"
MQTT_PORT="${MQTT_PORT:-1883}"
if [[ -n "${MQTT_HOST}" ]]; then
  ensure_cmd mosquitto_pub mosquitto-clients mosquitto || true
fi
if command -v mosquitto_pub >/dev/null 2>&1 && [[ -n "${MQTT_HOST}" ]]; then
  mosquitto_pub -h "${MQTT_HOST}" -p "${MQTT_PORT}" -t "test/sensitive" \
    -m "token=tok_123456789 otp=123456 email=alice@example.com" >/dev/null 2>&1 || true
fi

# Redis (non-HTTP) - optional; set REDIS_HOST (no safe public plaintext Redis)
if [[ -n "${REDIS_HOST:-}" ]]; then
  ensure_cmd redis-cli redis-tools redis || true
fi
if command -v redis-cli >/dev/null 2>&1 && [[ -n "${REDIS_HOST:-}" ]]; then
  REDIS_PORT="${REDIS_PORT:-6379}"
  REDIS_PASS="${REDIS_PASS:-}"
  if [[ -n "${REDIS_PASS}" ]]; then
    redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" -a "${REDIS_PASS}" ping >/dev/null 2>&1 || true
  else
    redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" ping >/dev/null 2>&1 || true
  fi
fi

# Raw TCP payload - public host (portquiz.net accepts TCP on any port)
RAW_TCP_HOST="${RAW_TCP_HOST:-portquiz.net}"
RAW_TCP_PORT="${RAW_TCP_PORT:-80}"
if [[ -n "${RAW_TCP_HOST}" && -n "${RAW_TCP_PORT}" ]]; then
  ensure_cmd nc netcat-openbsd nmap-ncat netcat ncat || true
fi
if command -v nc >/dev/null 2>&1 && [[ -n "${RAW_TCP_HOST}" && -n "${RAW_TCP_PORT}" ]]; then
  printf 'user=rawtester\npassword=RawPass123!\notp=999999\napi_key=RAW_API_ABC123\n' \
    | nc -w 3 "${RAW_TCP_HOST}" "${RAW_TCP_PORT}" >/dev/null 2>&1 || true
fi

# Repeat a few times to generate more packets
for i in 1 2 3; do
  curl "${CURL_OPTS[@]}" "${BASE_URL}/get?user=tester${i}&email=tester${i}%40example.com" -o /dev/null
done

echo "Done. Requests sent to ${BASE_URL}."
  