from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
import uvicorn
import asyncio
import threading
from scapy.all import sniff, conf, Ether, IP, TCP, UDP, ICMP, PcapReader, Raw, load_layer
from scapy.utils import PcapWriter
from scapy.layers.dns import DNS, DNSQR, DNSRR
try:
    load_layer("http")
    from scapy.layers.http import HTTPRequest
except ImportError:
    HTTPRequest = None
try:
    load_layer("tls")
    from scapy.layers.tls.all import TLSClientHello
except ImportError:
    TLSClientHello = None
from pydantic import BaseModel
import ipaddress
import json
import time
import os
import re
import shutil
import logging
import base64
import binascii
from urllib.parse import unquote_plus, parse_qsl
from typing import Optional

app = FastAPI(title="Packet Capture Tool")

MAX_FIELD_TEXT_CHARS = 512
MAX_FIELD_BYTES_PREVIEW = 256
CRED_REGEX = re.compile(rb'(?i)(username|user|usr|login|email|pwd|pass|password|token|api[_-]?key|secret)[=:]\s*([^&"\'\s]+)')
TEXT_CRED_REGEX = re.compile(r'(?i)\b(username|user|usr|login|email|pwd|pass|password|token|apikey|api_key|secret)\b[\s"\']{0,3}[:=]\s*["\']?([^&\s"\'\r\n;]+)')
TEXT_ANY_KV_REGEX = re.compile(r'(?im)\b([a-zA-Z][\w.\-\[\]]{0,80})\b\s*[:=]\s*["\']?([^&\r\n;]{1,240})')
FIELD_NAME_SAFE_REGEX = re.compile(r'^[A-Za-z0-9_.\-\[\]]{2,100}$')
BASIC_AUTH_REGEX = re.compile(r'(?im)^authorization:\s*basic\s+([A-Za-z0-9+/=]{8,})\s*$')
FTP_COMMAND_REGEX = re.compile(r'(?i)^(USER|PASS|ACCT|CWD|PWD|RETR|STOR|LIST|QUIT|AUTH|FEAT|SYST|TYPE|PORT|PASV|EPSV|EPRT|MKD|RMD|RNFR|RNTO)\b')
FTP_RESPONSE_REGEX = re.compile(r'^\d{3}[\s-]')
FTP_CRED_LINE_REGEX = re.compile(r'(?im)^(USER|PASS)\s+(.+)$')
SENSITIVE_KEY_REGEX = re.compile(r'(?i)(^|[_\-.\[\]])(username|user|usr|login|email|pwd|pass(word)?|token|api[_-]?key|secret|credential|auth)([_\-.\[\]]|$)')
FORM_INDEXED_PAIR_REGEX = re.compile(r'\[(\d+)\]\[(name|value)\]$', re.IGNORECASE)
METHOD_SUFFIX_REGEX = re.compile(r'\s+\[[^\]]+\]\s*$')
EMAIL_REGEX = re.compile(r'(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b')
PHONE_REGEX = re.compile(r'\b(?:\+?\d[\d\-\s]{7,}\d)\b')
URL_REGEX = re.compile(r'(?i)\bhttps?://[^\s]+')
JWT_REGEX = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
IMPORTANT_FIELD_HINT_REGEX = re.compile(r'(?i)(user|login|email|pass|pwd|token|secret|auth|credential|message|comment|content|text|note|description|desc|body|subject|phone|mobile|address|item_meta\[\d+\])')
NOISE_FIELD_PREFIXES = ("frm_", "form_", "_wp_")
NOISE_FIELD_NAMES = {
    "frm_action",
    "form_id",
    "form_key",
    "frm_submit_entry_2",
    "frm_state",
    "item_key",
    "unique_id",
    "nonce",
    "csrf",
    "action",
    "submit",
    "content-disposition",
    "name"
}
MAX_CRED_VALUE_LEN = 240
MAX_PAYLOAD_SCAN_BYTES = 8192
ENABLE_TLS_SNI = os.getenv("ENABLE_TLS_SNI", "0") == "1"

# Silence noisy Scapy warnings (e.g. unknown TLS cipher suites in malformed/legacy handshakes).
logging.getLogger("scapy").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
conf.verb = 0

# Store connected clients
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                print(f"Error sending to websocket: {e}")

manager = ConnectionManager()

# Global state for capturing
class CaptureState:
    def __init__(self):
        self.is_capturing = False
        self.interface = None
        self.packet_queue = asyncio.Queue()
        self.capture_thread = None
        self.loop = None
        self.packet_count = 0
        self.packet_cache = {} # id -> detailed packet info
        self.flow_states = {} # Stateful TCP tracking
        self.pcap_writer = None
        self.max_cache_size = 50000
        self.upload_batch_size = 250

capture_state = CaptureState()

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def get_index():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/api/interfaces")
async def get_interfaces():
    try:
        interfaces = []
        for iface in conf.ifaces.values():
            desc = getattr(iface, 'description', '')
            label = f"{iface.name}"
            if desc and desc != iface.name:
                label += f" - {desc}"
            interfaces.append({"id": iface.name, "label": label})
        return {"interfaces": interfaces}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class StartCaptureRequest(BaseModel):
    interface: str

def format_detail_value(val):
    if isinstance(val, (int, bool, float)):
        return val

    if isinstance(val, str):
        if len(val) <= MAX_FIELD_TEXT_CHARS:
            return val
        return f"{val[:MAX_FIELD_TEXT_CHARS]} ... (truncated {len(val)} chars)"

    if isinstance(val, bytes):
        preview = val[:MAX_FIELD_BYTES_PREVIEW]
        try:
            text = preview.decode('utf-8', 'replace')
        except Exception:
            text = preview.hex()
        if len(val) > MAX_FIELD_BYTES_PREVIEW:
            text += f" ... ({len(val)} bytes total)"
        return text

    text = str(val)
    if len(text) <= MAX_FIELD_TEXT_CHARS:
        return text
    return f"{text[:MAX_FIELD_TEXT_CHARS]} ... (truncated {len(text)} chars)"

def is_sensitive_key(key: str) -> bool:
    key_lower = str(key).lower()
    return bool(SENSITIVE_KEY_REGEX.search(key_lower))

def looks_metadata_noise(value: str) -> bool:
    value_lower = value.strip().lower()
    if not value_lower:
        return True

    if value_lower.startswith(("frm_", "form_", "_wp_")):
        return True
    if re.fullmatch(r'item_meta\[\d+\]', value_lower):
        return True
    if value_lower in {
        "item_key",
        "unique_id",
        "form_id",
        "frm_state",
        "submit",
        "action",
        "nonce",
        "csrf"
    }:
        return True

    if re.fullmatch(r'[a-f0-9]{24,}', value_lower):
        return True

    return False

def looks_metadata_field_name(field_name: str) -> bool:
    name = field_name.strip().lower()
    if not name:
        return True

    if name.startswith(("frm_", "form_", "_wp_")):
        return True
    if name in {"item_key", "unique_id", "nonce", "csrf", "action", "submit", "form_id"}:
        return True

    return False

def looks_user_visible_value(value: str) -> bool:
    val = str(value).strip()
    if len(val) < 1:
        return False
    if len(val) > MAX_CRED_VALUE_LEN:
        return False
    if val.startswith("--"):
        return False
    if "�" in val:
        return False
    if any(ord(ch) < 32 and ch not in "\t\r\n" for ch in val):
        return False

    printable_ratio = sum(1 for ch in val if ch.isprintable()) / len(val)
    if printable_ratio < 0.9:
        return False
    if not any(ch.isprintable() for ch in val):
        return False

    has_visible = any(ch.isalnum() for ch in val)
    if has_visible:
        return True

    return any(ch in "@#$%^&*()-_=+!?.:,/\\" for ch in val)

def extract_multipart_fields(payload_text: str):
    fields = []
    lines = payload_text.replace("\r\n", "\n").split("\n")
    i = 0

    while i < len(lines):
        line = lines[i]
        lower_line = line.lower()
        if "content-disposition:" not in lower_line or "form-data" not in lower_line or "name=" not in lower_line:
            i += 1
            continue

        name_match = re.search(r'name="([^"]+)"', line, flags=re.IGNORECASE)
        if not name_match:
            i += 1
            continue

        field_name = name_match.group(1).strip()
        i += 1

        # Skip optional headers before content.
        while i < len(lines) and lines[i].strip() != "":
            i += 1
        if i < len(lines) and lines[i].strip() == "":
            i += 1

        value_lines = []
        while i < len(lines):
            current = lines[i]
            if current.startswith("--"):
                break
            value_lines.append(current)
            i += 1

        field_value = "\n".join(value_lines).strip()
        fields.append((field_name, field_value))

    return fields

def maybe_decode_base64(value: str):
    candidate = value.strip()
    if len(candidate) < 8 or len(candidate) > 512:
        return None
    if len(candidate) % 4 != 0:
        return None
    if not re.fullmatch(r'[A-Za-z0-9+/=]+', candidate):
        return None
    try:
        decoded_raw = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return None
    decoded_text = decoded_raw.decode('utf-8', 'ignore').strip()
    if not decoded_text:
        return None
    if not any(ch.isprintable() for ch in decoded_text):
        return None
    return decoded_text

def extract_ftp_info(packet, sport: int, dport: int) -> str:
    if Raw not in packet:
        return f"FTP Port: {sport} -> {dport}"

    try:
        raw_text = packet[Raw].load[:200].decode('utf-8', 'ignore').strip()
    except Exception:
        raw_text = ""

    if not raw_text:
        return f"FTP Port: {sport} -> {dport}"

    first_line = raw_text.splitlines()[0].strip()
    if FTP_COMMAND_REGEX.match(first_line) or FTP_RESPONSE_REGEX.match(first_line):
        return f"FTP {first_line[:120]}"

    return f"FTP Data {sport} -> {dport}"

def extract_ftp_credentials(payload: bytes, src: str, dst: str, seen_keys):
    if not payload:
        return []

    text = payload[:MAX_PAYLOAD_SCAN_BYTES].decode('utf-8', 'ignore')
    if not text:
        return []

    results = []
    for match in FTP_CRED_LINE_REGEX.finditer(text):
        cmd = match.group(1).upper()
        value = match.group(2).strip()
        if not looks_user_visible_value(value):
            continue

        field = "username" if cmd == "USER" else "password"
        append_credential_result(results, seen_keys, src, dst, field, value, "ftp")

    return results

def strip_method_suffix(field: str) -> str:
    return METHOD_SUFFIX_REGEX.sub("", str(field)).strip().lower()

def is_noise_field_name(field_name: str) -> bool:
    name = strip_method_suffix(field_name)
    if not name:
        return True
    if name in NOISE_FIELD_NAMES:
        return True
    return any(name.startswith(prefix) for prefix in NOISE_FIELD_PREFIXES)

def is_likely_random_token(value: str) -> bool:
    val = str(value).strip()
    if len(val) < 24:
        return False
    if re.fullmatch(r'[a-f0-9]{24,}', val.lower()):
        return True
    if re.fullmatch(r'[A-Za-z0-9+/=_-]{24,}', val) and not any(ch in val for ch in '.:@/ '):
        if not EMAIL_REGEX.search(val) and not URL_REGEX.search(val) and not JWT_REGEX.match(val):
            return True
    return False

def cleartext_importance_score(field: str, value: str) -> int:
    field_name = strip_method_suffix(field)
    val = str(value).strip()

    if not field_name or not val:
        return -999
    if not looks_user_visible_value(val):
        return -999

    score = 0

    if is_noise_field_name(field_name):
        score -= 50
    if is_sensitive_key(field_name):
        score += 55
    if IMPORTANT_FIELD_HINT_REGEX.search(field_name):
        score += 35
    if re.fullmatch(r'item_meta\[\d+\]', field_name):
        score += 30

    if EMAIL_REGEX.search(val):
        score += 60
    if PHONE_REGEX.search(val):
        score += 35
    if URL_REGEX.search(val):
        score += 25
    if JWT_REGEX.match(val):
        score += 35

    if len(val) >= 4 and any(ch.isalpha() for ch in val):
        score += 20
    if len(val) >= 8 and (' ' in val or any(ord(ch) > 127 for ch in val)):
        score += 15

    if val.isdigit() and len(val) <= 3:
        score -= 45
    if is_likely_random_token(val) and not is_sensitive_key(field_name):
        score -= 20
    if looks_metadata_noise(val):
        score -= 25

    return score

def decode_base64url_text(segment: str):
    try:
        padded = segment + ('=' * (-len(segment) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode('utf-8'))
        text = decoded.decode('utf-8', 'ignore').strip()
        return text if text else None
    except Exception:
        return None

def decode_value_variants(value: str):
    raw = str(value).strip()
    variants = []

    if '%' in raw:
        decoded_url = unquote_plus(raw)
        if decoded_url and decoded_url != raw:
            variants.append(("url-decoded", decoded_url))

    decoded_b64 = maybe_decode_base64(raw)
    if decoded_b64 and decoded_b64 != raw:
        variants.append(("base64-decoded", decoded_b64))

    if JWT_REGEX.match(raw):
        parts = raw.split('.')
        if len(parts) == 3:
            payload_text = decode_base64url_text(parts[1])
            if payload_text:
                variants.append(("jwt-payload", payload_text))

    unique_variants = []
    seen_text = set()
    for method, text in variants:
        marker = (method, text)
        if marker in seen_text:
            continue
        seen_text.add(marker)
        unique_variants.append((method, text))
    return unique_variants

def looks_meaningful_decoded_text(text: str) -> bool:
    content = str(text).strip()
    if len(content) < 4:
        return False

    ascii_ratio = sum(1 for ch in content if ch.isascii() and ch.isprintable()) / len(content)
    if ascii_ratio < 0.75:
        return False

    if re.search(r'[A-Za-z]{3,}', content):
        return True

    return any(token in content for token in ('=', ':', '@', '&', '{', '}', 'http', '/', '.'))

def extract_inline_pairs(text: str):
    candidate = str(text).strip()
    if not candidate:
        return []

    pairs = []

    if '&' in candidate and '=' in candidate:
        try:
            pairs.extend(parse_qsl(candidate, keep_blank_values=True))
        except Exception:
            pass

    if candidate.startswith('{') and candidate.endswith('}'):
        try:
            parsed_json = json.loads(candidate)
            if isinstance(parsed_json, dict):
                for key, value in parsed_json.items():
                    if isinstance(value, (str, int, float, bool)):
                        pairs.append((str(key), str(value)))
        except Exception:
            pass

    for match in TEXT_ANY_KV_REGEX.finditer(candidate):
        key = match.group(1).strip()
        value = match.group(2).strip().strip('"\'')
        pairs.append((key, value))

    unique_pairs = []
    seen = set()
    for key, value in pairs:
        marker = (str(key).strip().lower(), str(value).strip())
        if marker in seen:
            continue
        seen.add(marker)
        unique_pairs.append((key, value))
    return unique_pairs

def select_important_cleartext_rows(rows, max_rows: int = 250):
    ranked = []

    for row in rows:
        source = row.get("source", "")
        destination = row.get("destination", "")
        field = row.get("field", "")
        value = str(row.get("value", ""))

        base_score = cleartext_importance_score(field, value)
        if base_score >= 25:
            ranked.append((base_score, {
                "source": source,
                "destination": destination,
                "field": field,
                "value": value
            }))

        for decode_method, decoded_text in decode_value_variants(value):
            if not looks_meaningful_decoded_text(decoded_text):
                continue
            decoded_score = cleartext_importance_score(field, decoded_text)
            if decoded_score >= 35 and decoded_text != value:
                ranked.append((decoded_score + 5, {
                    "source": source,
                    "destination": destination,
                    "field": f"{strip_method_suffix(field)} [{decode_method}]",
                    "value": decoded_text
                }))

            for key, pair_value in extract_inline_pairs(decoded_text)[:20]:
                pair_score = cleartext_importance_score(key, pair_value)
                if pair_score >= 30:
                    ranked.append((pair_score + 8, {
                        "source": source,
                        "destination": destination,
                        "field": f"{key} [{decode_method}]",
                        "value": str(pair_value)
                    }))

    ranked.sort(key=lambda item: item[0], reverse=True)

    selected = []
    dedupe = set()
    for score, row in ranked:
        dedupe_key = (
            row.get("source", ""),
            row.get("destination", ""),
            strip_method_suffix(row.get("field", "")),
            row.get("value", "")
        )
        if dedupe_key in dedupe:
            continue
        dedupe.add(dedupe_key)
        selected.append(row)
        if len(selected) >= max_rows:
            break

    return selected

def append_credential_result(results, seen_keys, src, dst, field, value, method):
    normalized_field = str(field).strip().lower()
    normalized_value = str(value).strip()
    if not normalized_field or not normalized_value:
        return
    if not FIELD_NAME_SAFE_REGEX.match(normalized_field):
        return
    if not looks_user_visible_value(normalized_value):
        return

    if len(normalized_value) > MAX_CRED_VALUE_LEN:
        normalized_value = normalized_value[:MAX_CRED_VALUE_LEN] + "..."

    dedupe_key = (src, dst, normalized_field, normalized_value)
    if dedupe_key in seen_keys:
        return

    seen_keys.add(dedupe_key)
    field_label = normalized_field if method == "plaintext" else f"{normalized_field} [{method}]"
    results.append({
        "source": src,
        "destination": dst,
        "field": field_label,
        "value": normalized_value
    })

def scan_credentials_in_text(text: str, src: str, dst: str, method: str, results, seen_keys):
    for match in TEXT_CRED_REGEX.finditer(text):
        field = match.group(1)
        value = match.group(2).strip().strip('"\'')
        append_credential_result(results, seen_keys, src, dst, field, value, method)

        decoded = maybe_decode_base64(value)
        if not decoded:
            continue

        if ':' in decoded:
            user, pwd = decoded.split(':', 1)
            append_credential_result(results, seen_keys, src, dst, "username", user, f"{method}+base64")
            append_credential_result(results, seen_keys, src, dst, "password", pwd, f"{method}+base64")

        for nested in TEXT_CRED_REGEX.finditer(decoded):
            append_credential_result(
                results,
                seen_keys,
                src,
                dst,
                nested.group(1),
                nested.group(2).strip().strip('"\''),
                f"{method}+base64"
            )

    for match in TEXT_ANY_KV_REGEX.finditer(text):
        field = match.group(1).strip()
        value = match.group(2).strip().strip('"\'')
        if not field or not looks_user_visible_value(value):
            continue
        append_credential_result(results, seen_keys, src, dst, field, value, method)

def extract_credentials_from_payload(payload: bytes, src: str, dst: str, seen_keys, is_http_request: bool = False):
    if not payload:
        return []

    sample = payload[:MAX_PAYLOAD_SCAN_BYTES]
    text = sample.decode('utf-8', 'replace')
    text_lower = text.lower()
    first_line = text.splitlines()[0].strip() if text else ""

    # Skip plain HTTP response payloads (CSS/JS/HTML noise) in Security clear-text table.
    if first_line.startswith("HTTP/"):
        return []

    http_req_match = re.match(r'^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+\S+\s+HTTP/\d', first_line)
    request_like = bool(http_req_match) or is_http_request

    # Cheap pre-filter to avoid expensive parsing on irrelevant payloads.
    if not any(token in text_lower for token in ("=", ":", "content-disposition", "{", "}", "?", "post ")):
        return []

    # Only process request-like payloads or body-like chunks (multipart/form/json/query fragments).
    if not request_like and not any(token in text_lower for token in ("content-disposition: form-data", "&", "=", "{")):
        return []

    results = []

    headers_part = ""
    body_part = text
    if "\r\n\r\n" in text:
        headers_part, body_part = text.split("\r\n\r\n", 1)
    elif "\n\n" in text:
        headers_part, body_part = text.split("\n\n", 1)

    body_for_parse = body_part.strip()

    if not request_like and "content-disposition: form-data" not in text_lower:
        return []

    if "content-disposition: form-data" in text_lower:
        multipart_fields = extract_multipart_fields(text)
        for field_name, field_value in multipart_fields:
            if not looks_user_visible_value(field_value):
                continue
            append_credential_result(results, seen_keys, src, dst, field_name, field_value, "multipart")

    if body_for_parse:
        try:
            pairs = parse_qsl(body_for_parse, keep_blank_values=True)
        except Exception:
            pairs = []

        pending_field = None
        indexed_fields = {}
        for key, value in pairs:
            key_clean = key.strip()
            key_lower = key_clean.lower()
            value_clean = value.strip()

            indexed_match = FORM_INDEXED_PAIR_REGEX.search(key_lower)
            if indexed_match:
                idx = indexed_match.group(1)
                kind = indexed_match.group(2).lower()
                if idx not in indexed_fields:
                    indexed_fields[idx] = {}
                indexed_fields[idx][kind] = value_clean

            if key_lower in {"name", "field_name", "input_name"}:
                pending_field = value_clean
                continue

            if key_lower in {"value", "field_value", "input_value"} and pending_field:
                if looks_user_visible_value(value_clean):
                    append_credential_result(results, seen_keys, src, dst, pending_field, value_clean, "form-decoded")
                pending_field = None
                continue

            if looks_user_visible_value(value_clean):
                append_credential_result(results, seen_keys, src, dst, key_clean, value_clean, "form-decoded")
            

        for pair in indexed_fields.values():
            field_name = pair.get("name", "").strip()
            field_value = pair.get("value", "").strip()
            if field_name and looks_user_visible_value(field_value):
                append_credential_result(results, seen_keys, src, dst, field_name, field_value, "form-decoded")

    scan_target = body_part if body_part else text
    if "content-disposition: form-data" not in text_lower:
        scan_credentials_in_text(scan_target, src, dst, "plaintext", results, seen_keys)

    if '%' in text:
        decoded_url = unquote_plus(text)
        if decoded_url != text:
            scan_credentials_in_text(decoded_url, src, dst, "url-decoded", results, seen_keys)

    for token in BASIC_AUTH_REGEX.findall(text):
        decoded_auth = maybe_decode_base64(token)
        if decoded_auth and ':' in decoded_auth:
            user, pwd = decoded_auth.split(':', 1)
            append_credential_result(results, seen_keys, src, dst, "username", user, "basic-auth")
            append_credential_result(results, seen_keys, src, dst, "password", pwd, "basic-auth")

    try:
        first_line = text.splitlines()[0] if text else ""
        if ' ' in first_line and '?' in first_line:
            parts = first_line.split(' ')
            if len(parts) >= 2 and '?' in parts[1]:
                query_str = parts[1].split('?', 1)[1]
                for key, value in parse_qsl(query_str, keep_blank_values=True):
                    if looks_user_visible_value(value):
                        append_credential_result(results, seen_keys, src, dst, key, value, "query-string")
    except Exception:
        pass

    try:
        if "{" in text and "}" in text:
            body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else text
            body = body.strip()
            if body.startswith("{") and body.endswith("}"):
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    for key, value in parsed.items():
                        if isinstance(value, (str, int, float, bool)) and looks_user_visible_value(value):
                            append_credential_result(results, seen_keys, src, dst, key, value, "json")
    except Exception:
        pass

    return results

def packet_to_dict(packet):
    layers = []
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break
        
        layer_name = layer.name
        fields = {}
        for field in layer.fields_desc:
            val = getattr(layer, field.name, None)
            fields[field.name] = format_detail_value(val)
        
        layers.append({"layer": layer_name, "fields": fields})
        counter += 1
    return layers

def cache_packet_detail(pkt_id: int, detail):
    capture_state.packet_cache[pkt_id] = detail
    oldest_id = pkt_id - capture_state.max_cache_size
    if oldest_id > 0:
        capture_state.packet_cache.pop(oldest_id, None)

def build_packet_summary(packet, pkt_id: int):
    timestamp = float(getattr(packet, "time", time.time()))
    src = "Unknown"
    dst = "Unknown"
    sport = 0
    dport = 0
    proto = "Unknown"
    length = len(packet)
    info = ""

    if Ether in packet:
        src = packet[Ether].src
        dst = packet[Ether].dst
        proto = "Ethernet"

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "IP"
        info = f"TTL={packet[IP].ttl}"

    if TCP in packet:
        proto = "TCP"
        tcp = packet[TCP]
        sport = tcp.sport
        dport = tcp.dport
        info = f"Port: {tcp.sport} -> {tcp.dport} Flags: {tcp.flags}"

        # TCP Expert System (Stateful)
        src_endpoint = f"{src}:{tcp.sport}"
        dst_endpoint = f"{dst}:{tcp.dport}"
        flow_key = tuple(sorted([src_endpoint, dst_endpoint]))

        if flow_key not in capture_state.flow_states:
            capture_state.flow_states[flow_key] = {'syn_time': {}, 'last_seq': {}, 'last_ack': {}}
        state = capture_state.flow_states[flow_key]

        payload_len = len(tcp.payload)
        if src_endpoint in state['last_seq']:
            if tcp.seq == state['last_seq'][src_endpoint] and payload_len > 0:
                info += " [TCP Retransmission]"
            elif tcp.ack == state['last_ack'].get(src_endpoint) and payload_len == 0 and not (tcp.flags & 0x17):
                info += " [TCP Dup ACK]"

        state['last_seq'][src_endpoint] = tcp.seq
        state['last_ack'][src_endpoint] = tcp.ack

        if 'S' in tcp.flags and 'A' not in tcp.flags:
            state['syn_time'][src_endpoint] = timestamp
            info += " [TCP SYN]"
        elif 'S' in tcp.flags and 'A' in tcp.flags:
            if dst_endpoint in state['syn_time']:
                rtt = timestamp - state['syn_time'][dst_endpoint]
                info += f" [TCP SYN/ACK] RTT: {rtt*1000:.2f}ms"
                del state['syn_time'][dst_endpoint]
        elif 'R' in tcp.flags:
            info += " [TCP RST]"

        if HTTPRequest is not None and packet.haslayer(HTTPRequest):
            proto = "HTTP"
            http_layer = packet.getlayer(HTTPRequest)
            method = http_layer.Method.decode('utf-8', 'ignore') if http_layer.Method else ""
            path = http_layer.Path.decode('utf-8', 'ignore') if http_layer.Path else ""
            host = http_layer.Host.decode('utf-8', 'ignore') if http_layer.Host else ""
            info = f"{method} {host}{path}"

            if method == "POST" and Raw in packet:
                payload = packet[Raw].load
                matches = CRED_REGEX.findall(payload)
                if matches:
                    exposed = [f"{m[0].decode('utf-8','ignore')}={m[1].decode('utf-8','ignore')}" for m in matches]
                    info = f"[ALERT] Exposed Credential: {', '.join(exposed)}"

        elif tcp.sport in (20, 21) or tcp.dport in (20, 21):
            proto = "FTP"
            info = extract_ftp_info(packet, tcp.sport, tcp.dport)

        elif ENABLE_TLS_SNI and TLSClientHello is not None and packet.haslayer(TLSClientHello):
            proto = "TLS"
            ch = packet.getlayer(TLSClientHello)
            sni = ""
            if hasattr(ch, 'ext'):
                for ext in ch.ext:
                    if getattr(ext, 'type', None) == 0: # ServerName
                        try:
                            sni = ext.servernames[0].servername.decode('utf-8', 'ignore')
                        except:
                            pass
            if sni:
                info += f" SNI: {sni}"

    elif UDP in packet:
        proto = "UDP"
        udp = packet[UDP]
        sport = udp.sport
        dport = udp.dport
        info = f"Port: {udp.sport} -> {udp.dport}"

    elif ICMP in packet:
        proto = "ICMP"
        icmp = packet[ICMP]
        info = f"Type={icmp.type} Code={icmp.code}"

    # Check DNS for both UDP and TCP
    if packet.haslayer(DNS):
        proto = "DNS"
        dns = packet.getlayer(DNS)
        if hasattr(dns, 'qr') and hasattr(dns, 'qd') and dns.qd:
            qname = dns.qd.qname.decode('utf-8', 'ignore').rstrip('.')
            if dns.qr == 0:
                info = f"Query {qname}"
            else:
                if dns.rcode == 3:
                    info = f"Response [NXDOMAIN] {qname}"
                else:
                    info = f"Response {qname}"

    detail = packet_to_dict(packet)

    return {
        "id": pkt_id,
        "timestamp": timestamp,
        "src": src,
        "sport": sport,
        "dst": dst,
        "dport": dport,
        "protocol": proto,
        "length": length,
        "info": info,
        "detail": detail
    }

def packet_handler(packet):
    if not capture_state.is_capturing:
        return
        
    if capture_state.pcap_writer:
        capture_state.pcap_writer.write(packet)
    
    # Run parsing in background to avoid blocking sniff
    if capture_state.loop and capture_state.packet_queue:
        try:
            capture_state.packet_count += 1
            pkt_id = capture_state.packet_count
            summary = build_packet_summary(packet, pkt_id)
            cache_packet_detail(pkt_id, summary["detail"])

            # Push to queue to be broadcasted
            asyncio.run_coroutine_threadsafe(
                capture_state.packet_queue.put({"type": "packet", "data": summary}),
                capture_state.loop
            )
        except Exception as e:
            print(f"Error handling packet: {e}")

def capture_task(interface):
    print(f"Starting capture on {interface}")
    try:
        sniff(iface=interface, prn=packet_handler, store=False, 
              stop_filter=lambda p: not capture_state.is_capturing)
    except Exception as e:
        print(f"Sniff error: {e}")
        # Send error to clients
        if capture_state.loop:
             asyncio.run_coroutine_threadsafe(
                manager.broadcast(json.dumps({"type": "error", "message": str(e)})), 
                capture_state.loop
            )
    print("Capture stopped.")

@app.post("/api/capture/start")
async def start_capture(request: StartCaptureRequest):
    if capture_state.is_capturing:
        return {"status": "already capturing"}

    capture_state.interface = request.interface
    capture_state.is_capturing = True
    capture_state.loop = asyncio.get_running_loop()
    capture_state.packet_cache.clear()
    capture_state.flow_states.clear()
    capture_state.packet_count = 0
    
    if os.path.exists("session.pcap"):
        try:
            os.remove("session.pcap")
        except:
            pass
    capture_state.pcap_writer = PcapWriter("session.pcap", append=True, sync=True)
    
    # Start scapy sniff in a separate thread so it doesn't block the async event loop
    capture_state.capture_thread = threading.Thread(target=capture_task, args=(request.interface,))
    capture_state.capture_thread.daemon = True
    capture_state.capture_thread.start()
    
    return {"status": "started", "interface": request.interface}

@app.post("/api/capture/stop")
async def stop_capture():
    if not capture_state.is_capturing:
         return {"status": "not capturing"}
    
    capture_state.is_capturing = False
    if capture_state.pcap_writer:
        capture_state.pcap_writer.close()
        capture_state.pcap_writer = None
    # Scapy's sniff will eventually see stop_filter=True and exit the thread
    return {"status": "stopped"}

@app.get("/api/packet/{packet_id}")
async def get_packet_detail(packet_id: int):
    detail = capture_state.packet_cache.get(packet_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Packet not found or expired from cache")
    return {"id": packet_id, "detail": detail}

def is_internal(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False

@app.get("/api/analyze")
async def analyze_capture():
    if not os.path.exists("session.pcap"):
        raise HTTPException(status_code=404, detail="No capture data found.")
    
    total_packets = 0
    start_time = None
    end_time = None
    hosts_observed = set()
    external_dests = set()
    tcp_resets = 0
    dns_nxdomain = 0
    protocols = {}
    
    io_graph = {}
    credentials = []
    credential_seen = set()
    flows = {}
    dns_queries = {}
    raw_timeline = []
    
    try:
        with PcapReader("session.pcap") as pcap_reader:
            for packet in pcap_reader:
                total_packets += 1
                pkt_time = float(packet.time)
                if start_time is None:
                    start_time = pkt_time
                end_time = pkt_time
                
                second_bucket = int(pkt_time - start_time)
                if second_bucket not in io_graph:
                    io_graph[second_bucket] = {"bytes": 0, "packets": 0}
                io_graph[second_bucket]["bytes"] += len(packet)
                io_graph[second_bucket]["packets"] += 1
                
                if IP in packet:
                    src = packet[IP].src
                    dst = packet[IP].dst
                    hosts_observed.add(src)
                    hosts_observed.add(dst)
                    
                    if not is_internal(dst):
                        external_dests.add(dst)
                        
                    sport, dport = 0, 0
                    proto = "IP"
                    tcp_flags = ""
                    cleartext_count = 0
                    
                    if TCP in packet:
                        tcp = packet[TCP]
                        sport = tcp.sport
                        dport = tcp.dport
                        proto = "TCP"
                        tcp_flags = str(tcp.flags)

                        if tcp.sport in (20, 21) or tcp.dport in (20, 21):
                            proto = "FTP"
                        
                        if 'R' in tcp_flags:
                            tcp_resets += 1
                            
                        if Raw in packet:
                            payload = packet[Raw].load
                            if len(credentials) < 5000:
                                is_http_request_packet = HTTPRequest is not None and packet.haslayer(HTTPRequest)
                                extracted = extract_credentials_from_payload(
                                    payload,
                                    src,
                                    dst,
                                    credential_seen,
                                    is_http_request=is_http_request_packet
                                )

                                if tcp.sport in (20, 21) or tcp.dport in (20, 21):
                                    extracted.extend(extract_ftp_credentials(payload, src, dst, credential_seen))

                                if extracted:
                                    credentials.extend(extracted)
                                    cleartext_count += len(extracted)
                    elif UDP in packet:
                        sport = packet[UDP].sport
                        dport = packet[UDP].dport
                        proto = "UDP"
                    elif packet.haslayer(ICMP):
                        proto = "ICMP"
                    
                    protocols[proto] = protocols.get(proto, 0) + 1
                    
                    metadata = {}
                    if cleartext_count > 0:
                        metadata["cleartext_exposed"] = f"{cleartext_count} fields"
                    
                    if packet.haslayer(DNS):
                        dns = packet.getlayer(DNS)
                        if hasattr(dns, 'qd') and dns.qd:
                            qname = dns.qd.qname.decode('utf-8', 'ignore').rstrip('.')
                            metadata["dns_query"] = qname
                            if qname not in dns_queries:
                                dns_queries[qname] = {"count": 0, "nxdomain": 0, "ok": 0}
                            dns_queries[qname]["count"] += 1
                            
                            if getattr(dns, 'qr', 0) == 0:
                                dns_queries[qname]["count"] += 1
                                raw_timeline.append({
                                    "time": pkt_time,
                                    "type": "DNS_QUERY",
                                    "desc": f"{src} queried DNS for {qname}",
                                    "host": src
                                })
                            else:
                                if getattr(dns, 'rcode', 0) == 3:
                                    dns_queries[qname]["nxdomain"] += 1
                                    dns_nxdomain += 1
                                else:
                                    dns_queries[qname]["ok"] += 1
                                    
                    if ENABLE_TLS_SNI and TLSClientHello is not None and packet.haslayer(TLSClientHello):
                        try:
                            for ext in packet[TLSClientHello].ext:
                                if hasattr(ext, 'servernames'):
                                    sni = ext.servernames[0].servername.decode('utf-8')
                                    metadata["tls_sni"] = sni
                        except:
                            pass
                    
                    flow_key = tuple(sorted([(src, sport), (dst, dport)]) + [proto])
                    
                    if flow_key not in flows:
                        flows[flow_key] = {
                            "client_ip": src,
                            "client_port": sport,
                            "server_ip": dst,
                            "server_port": dport,
                            "protocol": proto,
                            "start_time": pkt_time,
                            "end_time": pkt_time,
                            "packet_count": 0,
                            "bytes_out": 0,
                            "bytes_in": 0,
                            "tcp_flags": set(),
                            "metadata": {},
                            "packet_nos": []
                        }
                        raw_timeline.append({
                            "time": pkt_time,
                            "type": "FLOW_START",
                            "desc": f"Host {src} initiated {proto} connection to {dst}:{dport}",
                            "host": src
                        })
                    
                    flow = flows[flow_key]
                    flow["end_time"] = pkt_time
                    flow["packet_count"] += 1
                    flow["packet_nos"].append(total_packets)
                    if tcp_flags:
                        for f in tcp_flags:
                            flow["tcp_flags"].add(f)
                            
                    if src == flow["client_ip"]:
                        flow["bytes_out"] += len(packet)
                    else:
                        flow["bytes_in"] += len(packet)
                        
                    for k, v in metadata.items():
                        if k not in flow["metadata"]:
                            flow["metadata"][k] = set()
                        flow["metadata"][k].add(v)
                        
        suspicious_flows = []
        long_lived_flows = 0
        lateral_movement_candidates = {}
        
        for key, f in flows.items():
            f["duration"] = f["end_time"] - f["start_time"]
            if f["duration"] > 60:
                long_lived_flows += 1
                
            risk_score = 0
            evidence = []
            
            if f["protocol"] == "TCP":
                flags = f["tcp_flags"]
                if 'S' in flags and 'A' not in flags:
                    risk_score += 3
                    evidence.append("SYN without SYN/ACK (Possible scan/unreachable)")
                if 'R' in flags and f["packet_count"] < 5:
                    risk_score += 2
                    evidence.append("RST on short connection")
                    
            if is_internal(f["client_ip"]) and is_internal(f["server_ip"]):
                if f["server_port"] in [445, 3389, 22, 1433, 5985]:
                    client = f["client_ip"]
                    if client not in lateral_movement_candidates:
                        lateral_movement_candidates[client] = set()
                    lateral_movement_candidates[client].add(f["server_ip"])
                    
            formatted_meta = []
            for k, v in f["metadata"].items():
                formatted_meta.append(f"{k}: {', '.join(v)}")
            f["metadata_str"] = " | ".join(formatted_meta)
            
            if f["bytes_out"] > 500000 and f["bytes_in"] < f["bytes_out"] * 0.1:
                risk_score += 5
                evidence.append(f"Large outbound transfer ({(f['bytes_out']/1024):.1f} KB)")

            if "cleartext_exposed" in f["metadata"]:
                risk_score += 4
                evidence.append("Clear-text fields exposed in payload")
                
            if risk_score > 0:
                filter_str = f"ip.addr == {f['client_ip']} && ip.addr == {f['server_ip']} && {f['protocol'].lower()}.port == {f['server_port']}"
                suspicious_flows.append({
                    "flow": f"{f['client_ip']}:{f['client_port']} -> {f['server_ip']}:{f['server_port']} ({f['protocol']})",
                    "risk_score": risk_score,
                    "evidence": evidence,
                    "metadata": f["metadata_str"],
                    "packets": f"[{f['packet_count']} pkts] {f['packet_nos'][0]} ... {f['packet_nos'][-1]}",
                    "packet_nos": f["packet_nos"],
                    "wireshark_filter": filter_str
                })
                
        for client, servers in lateral_movement_candidates.items():
            if len(servers) > 2:
                suspicious_flows.append({
                    "flow": f"{client} -> Multiple Internal Hosts",
                    "risk_score": 8,
                    "evidence": [f"Lateral movement: connected to {len(servers)} internal hosts on sensitive ports (SMB/RDP/SSH)."],
                    "metadata": "",
                    "packets": "Multiple flows"
                })

        dns_anomalies = []
        suspicious_names = 0
        for domain, stats in sorted(dns_queries.items(), key=lambda x: x[1]["count"], reverse=True)[:50]:
            is_anomaly = False
            evidence = []
            if len(domain) > 50:
                is_anomaly = True
                evidence.append("Long domain name")
                suspicious_names += 1
            if stats["nxdomain"] > 0 and stats["nxdomain"] / stats["count"] > 0.5:
                is_anomaly = True
                evidence.append(f"High NXDOMAIN ratio ({stats['nxdomain']}/{stats['count']})")
                
            dns_anomalies.append({
                "domain": domain,
                "count": stats["count"],
                "nxdomain": stats["nxdomain"],
                "evidence": evidence,
                "is_anomaly": is_anomaly,
                "wireshark_filter": f'dns.qry.name contains "{domain}"'
            })
                
        duration_str = f"{end_time - start_time:.2f}s" if start_time and end_time else "0s"
        
        host_bytes = {}
        for f in flows.values():
            c_ip, s_ip = f["client_ip"], f["server_ip"]
            host_bytes[c_ip] = host_bytes.get(c_ip, 0) + f["bytes_out"] + f["bytes_in"]
            host_bytes[s_ip] = host_bytes.get(s_ip, 0) + f["bytes_out"] + f["bytes_in"]
            
        top_talkers = [k for k, v in sorted(host_bytes.items(), key=lambda x: x[1], reverse=True)[:3]]
        top_protos = [p[0] for p in sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:3]]
        
        summary = {
            "duration": duration_str,
            "total_packets": total_packets,
            "hosts_observed": len(hosts_observed),
            "external_dests": len(external_dests),
            "top_talkers": ", ".join(top_talkers),
            "top_protocols": ", ".join(top_protos),
            "tcp_resets": tcp_resets,
            "dns_nxdomain": dns_nxdomain,
            "long_lived_flows": long_lived_flows,
            "suspicious_names": suspicious_names
        }

        io_list = [{"time": k, "bytes": v["bytes"], "packets": v["packets"]} for k, v in sorted(io_graph.items())]
        suspicious_flows.sort(key=lambda x: x["risk_score"], reverse=True)
        credentials = select_important_cleartext_rows(credentials, max_rows=300)
        
        # Format Timeline
        raw_timeline.sort(key=lambda x: x["time"])
        formatted_timeline = []
        for evt in raw_timeline[:200]: # Limit to 200 events to prevent massive output
            import datetime
            time_str = datetime.datetime.fromtimestamp(evt["time"]).strftime('%H:%M:%S')
            formatted_timeline.append(f"{time_str} | {evt['desc']}")

        top_flow_list = []
        for key, f in sorted(flows.items(), key=lambda x: x[1]["bytes_out"] + x[1]["bytes_in"], reverse=True)[:50]:
            top_flow_list.append({
                "flow": f"{f['client_ip']}:{f['client_port']} <-> {f['server_ip']}:{f['server_port']} ({f['protocol']})",
                "packets": f["packet_count"],
                "bytes": f["bytes_out"] + f["bytes_in"]
            })

        return {
            "summary": summary,
            "suspicious_flows": suspicious_flows[:100],
            "top_flows": top_flow_list,
            "dns_anomalies": dns_anomalies,
            "timeline": formatted_timeline,
            "io_graph": io_list,
            "credentials": credentials,
            "cleartext_fields": credentials
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

class EvidenceRequest(BaseModel):
    packet_nos: list[int]

@app.post("/api/download_evidence")
async def download_evidence(req: EvidenceRequest):
    if not os.path.exists("session.pcap"):
        raise HTTPException(status_code=404, detail="No capture data found.")
    
    nos_set = set(req.packet_nos)
    evidence_file = "evidence.pcap"
    
    try:
        current_no = 1
        with PcapWriter(evidence_file, append=False, sync=True) as pcap_writer:
            with PcapReader("session.pcap") as pcap_reader:
                for packet in pcap_reader:
                    if current_no in nos_set:
                        pcap_writer.write(packet)
                    current_no += 1
        return FileResponse(evidence_file, filename="evidence.pcap", media_type="application/vnd.tcpdump.pcap")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/download")
async def download_pcap():
    if not os.path.exists("session.pcap"):
        raise HTTPException(status_code=404, detail="No capture data found.")
    return FileResponse("session.pcap", filename="session.pcap", media_type="application/vnd.tcpdump.pcap")

@app.get("/api/stream")
async def get_tcp_stream(src_ip: str, src_port: int, dst_ip: str, dst_port: int):
    if not os.path.exists("session.pcap"):
        raise HTTPException(status_code=404, detail="No capture data found.")
    
    stream_data = []
    try:
        with PcapReader("session.pcap") as pcap_reader:
            for packet in pcap_reader:
                if IP in packet and TCP in packet:
                    p_src = packet[IP].src
                    p_dst = packet[IP].dst
                    p_sport = packet[TCP].sport
                    p_dport = packet[TCP].dport
                    
                    if (p_src == src_ip and p_sport == src_port and p_dst == dst_ip and p_dport == dst_port) or \
                       (p_src == dst_ip and p_sport == dst_port and p_dst == src_ip and p_dport == src_port):
                        if Raw in packet:
                            payload = packet[Raw].load
                            direction = "client_to_server" if p_src == src_ip else "server_to_client"
                            try:
                                text = payload.decode('utf-8', errors='replace')
                            except:
                                text = str(payload)
                            stream_data.append({"direction": direction, "payload": text})
        return {"stream": stream_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/upload")
async def upload_pcap(file: UploadFile = File(...)):
    if capture_state.is_capturing:
        raise HTTPException(status_code=400, detail="Cannot upload while capturing.")
    
    file_path = "session.pcap"
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    try:
        file_size = os.path.getsize(file_path)
        if file_size >= 500 * 1024 * 1024:
            capture_state.upload_batch_size = 500
        elif file_size >= 150 * 1024 * 1024:
            capture_state.upload_batch_size = 350
        else:
            capture_state.upload_batch_size = 250
    except Exception:
        capture_state.upload_batch_size = 250
        
    capture_state.packet_cache.clear()
    capture_state.flow_states.clear()
    capture_state.packet_count = 0
    capture_state.is_capturing = True 
    capture_state.loop = asyncio.get_running_loop()
    
    def playback_task():
        print(f"Playback started for {file.filename}")
        batch = []

        def flush_batch(items):
            if not items or not capture_state.loop:
                return
            try:
                asyncio.run_coroutine_threadsafe(
                    capture_state.packet_queue.put({"type": "packet_batch", "data": list(items)}),
                    capture_state.loop
                )
            except Exception as batch_err:
                print(f"Failed to queue packet batch: {batch_err}")

        try:
            with PcapReader("session.pcap") as pcap_reader:
                for packet in pcap_reader:
                    if not capture_state.is_capturing:
                        break

                    capture_state.packet_count += 1
                    pkt_id = capture_state.packet_count
                    summary = build_packet_summary(packet, pkt_id)
                    cache_packet_detail(pkt_id, summary["detail"])

                    batch.append(summary)
                    if len(batch) >= capture_state.upload_batch_size:
                        flush_batch(batch)
                        batch = []

                if batch:
                    flush_batch(batch)
        except Exception as e:
            print(f"Playback error: {e}")
            if capture_state.loop:
                 asyncio.run_coroutine_threadsafe(
                    manager.broadcast(json.dumps({"type": "error", "message": str(e)})), 
                    capture_state.loop
                )
        print("Playback finished.")
        capture_state.is_capturing = False
        if capture_state.loop:
             asyncio.run_coroutine_threadsafe(
                manager.broadcast(json.dumps({"type": "status", "message": "Playback finished"})), 
                capture_state.loop
            )

    capture_state.pcap_writer = None 
    
    capture_state.capture_thread = threading.Thread(target=playback_task)
    capture_state.capture_thread.daemon = True
    capture_state.capture_thread.start()

    return {"status": "success"}

async def consume_queue_and_broadcast():
    while True:
        try:
            packet_message = await capture_state.packet_queue.get()
            message = json.dumps(packet_message)
            await manager.broadcast(message)
            capture_state.packet_queue.task_done()
        except Exception as e:
            print(f"Error broadcasting: {e}")
            await asyncio.sleep(1)

@app.on_event("startup")
async def startup_event():
    # Start background task to broadcast packets
    asyncio.create_task(consume_queue_and_broadcast())

@app.websocket("/ws/packets")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We don't really expect to receive much, but keep the connection open
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        manager.disconnect(websocket)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
