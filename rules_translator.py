"""
rules_translator.py
====================
Bộ dịch bộ lọc ngôn ngữ tự nhiên → Wireshark Display Filter.

Kiến trúc tinh gọn:
  Tầng 1 — Local Rules  : Regex/keyword, cực nhanh, không cần mạng.
  Tầng 2 — Gemini AI    : Dịch bằng Google Gemini API.
  Tầng 3 — Heuristic    : Luôn trả về kết quả nếu AI thất bại hoặc hết quota.

Cấu hình trong .env:
  GEMINI_API_KEY = "..."
"""

import re
import os
import json
import asyncio
import urllib.request
import urllib.error
from typing import Optional
from pydantic import BaseModel


class TranslateFilterRequest(BaseModel):
    query: str


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------

class AIProviderError(Exception):
    """Lỗi chung khi gọi AI provider."""
    def __init__(self, provider: str, reason: str, permanent: bool = False):
        self.provider = provider
        self.reason = reason
        self.permanent = permanent
        super().__init__(f"[{provider}] {reason}")


class GeminiQuotaExhaustedError(AIProviderError):
    """Lỗi chuyên biệt khi Gemini hết quota."""
    pass


# ---------------------------------------------------------------------------
# Hằng số & bảng ánh xạ cho Local Rules (Tầng 1)
# ---------------------------------------------------------------------------

VALID_PROTOCOLS = {
    "tcp", "udp", "http", "https", "dns", "icmp", "tls", "ftp", "arp",
    "ip", "ipv6", "smtp", "pop3", "imap", "ssh", "rdp", "smb",
}

PROTO_ALIASES: dict[str, str] = {
    "giao thức điều khiển truyền": "TCP",
    "giao thức datagram người dùng": "UDP",
    "web": "HTTP",
    "tên miền": "DNS",
    "hệ thống tên miền": "DNS",
    "bảo mật": "TLS",
    "mã hóa": "TLS",
    "truyền file": "FTP",
    "ftp": "FTP",
    "ping": "ICMP",
    "icmp": "ICMP",
    "arp": "ARP",
    "phân giải địa chỉ": "ARP",
    "secure": "TLS",
    "encrypted": "TLS",
    "file transfer": "FTP",
    "domain": "DNS",
    "name resolution": "DNS",
    "web traffic": "HTTP",
}

SRC_KEYWORDS = {"từ", "from", "src", "source", "gửi từ", "xuất phát từ"}
DST_KEYWORDS = {"đến", "tới", "to", "dst", "destination", "gửi đến", "tới đích"}

LEN_FIELD_RE = re.compile(
    r"(?:độ dài|kích thước|len(?:gth)?|dung lượng|size)\s*"
    r"(?P<op>lớn hơn|nhỏ hơn|bằng|>=|<=|>|<|==)\s*"
    r"(?P<val>[0-9]+)",
    re.IGNORECASE | re.UNICODE,
)
LEN_OP_MAP = {
    "lớn hơn": ">", ">": ">", ">=": ">=",
    "nhỏ hơn": "<", "<": "<", "<=": "<=",
    "bằng": "==", "==": "==",
}

IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
PORT_EXPLICIT_RE = re.compile(
    r"(?:port|cổng(?:\s+số)?)\s+([0-9]{1,5})", re.IGNORECASE | re.UNICODE
)
FRAME_RE = re.compile(
    r"(?:gói tin số|gói số|gói|frame|packet)\s+#?([0-9]+)",
    re.IGNORECASE | re.UNICODE,
)
DOMAIN_RE = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9]{2,})+)\b"
)

WIRESHARK_OPS = ("==", "!=", ">=", "<=", "&&", "||", "contains", "matches")
WIRESHARK_FIELD_PREFIXES = (
    "ip.", "tcp.", "udp.", "dns.", "http.", "tls.", "ftp.", "arp.",
    "frame.", "eth.", "icmp.", "protocol ==", "protocol !=",
)

TCP_ERROR_KEYWORDS = {"lỗi", "error", "retransmission", "dup ack", "duplicate ack", "out-of-order"}
PAYLOAD_KEYWORDS   = {"payload", "nội dung", "dữ liệu", "data", "content", "body"}
IMAGE_KEYWORDS     = {"ảnh", "image", "png", "jpg", "jpeg", "gif", "webp", "media", "hình"}


# ---------------------------------------------------------------------------
# Tầng 1: Local Rules
# ---------------------------------------------------------------------------

def translate_local_rules(query: str) -> Optional[str]:
    """
    Dịch cục bộ không cần AI.
    Trả về filter string hoặc None nếu cần AI xử lý.
    """
    q = query.strip()
    q_lower = q.lower()

    if not q_lower:
        return None

    # 1. Lọc theo độ dài
    m = LEN_FIELD_RE.search(q_lower)
    if m:
        op = LEN_OP_MAP.get(m.group("op").strip(), ">")
        return f"frame.len {op} {m.group('val')}"

    # 2. Đã là Wireshark filter hợp lệ → dùng thẳng
    if any(op in q for op in WIRESHARK_OPS) and any(pf in q_lower for pf in WIRESHARK_FIELD_PREFIXES):
        return q

    # 3. Tên giao thức đơn thuần
    if q_lower in VALID_PROTOCOLS:
        return _proto_filter(q_lower)

    # 4. Frame / packet number
    m = FRAME_RE.search(q_lower)
    if m:
        return f"frame.number == {m.group(1)}"

    # 5. Ảnh / content-type
    if any(kw in q_lower for kw in IMAGE_KEYWORDS):
        return 'http.content_type contains "image"'

    # 5b. Checksum errors
    if any(kw in q_lower for kw in ["checksum sai", "checksum lỗi", "bad checksum", "incorrect checksum", "sai checksum", "lỗi checksum", "checksum không đúng"]):
        return "ip.checksum.status == 2 || tcp.checksum.status == 2 || udp.checksum.status == 2"

    # 5c. Broadcast / Multicast
    if "broadcast" in q_lower:
        return "eth.dst == ff:ff:ff:ff:ff:ff"
    if "multicast" in q_lower:
        return "ip.dst >= 224.0.0.0"

    # 5d. HTTP Methods & Response codes
    if "http post" in q_lower or "gửi post" in q_lower:
        return 'http.request.method == "POST"'
    if "http get" in q_lower or "gửi get" in q_lower:
        return 'http.request.method == "GET"'
    if "404" in q_lower and "http" in q_lower:
        return "http.response.code == 404"

    # 5e. VLAN tagged packets
    if "vlan" in q_lower:
        return "vlan"

    # 6. TCP errors
    if any(kw in q_lower for kw in TCP_ERROR_KEYWORDS) and "tcp" in q_lower:
        return "tcp.analysis.flags"

    # 7. TCP payload
    if any(kw in q_lower for kw in PAYLOAD_KEYWORDS) and "tcp" in q_lower:
        return "tcp.len > 0"

    # 8. IP + Port + Protocol + Domain
    conditions = []

    ips = IPV4_RE.findall(q_lower)
    for ip in ips:
        idx = q_lower.find(ip)
        prefix = q_lower[max(0, idx - 25):idx]
        if any(kw in prefix for kw in SRC_KEYWORDS):
            conditions.append(f"ip.src == {ip}")
        elif any(kw in prefix for kw in DST_KEYWORDS):
            conditions.append(f"ip.dst == {ip}")
        else:
            conditions.append(f"ip.addr == {ip}")

    ports = PORT_EXPLICIT_RE.findall(q_lower)
    ip_segs = {seg for ip in ips for seg in ip.split(".")}
    for p in ports:
        if p not in ip_segs and 1 <= int(p) <= 65535:
            proto_prefix = "udp" if "udp" in q_lower else "tcp"
            conditions.append(f"{proto_prefix}.port == {p}")

    for alias, proto in PROTO_ALIASES.items():
        if alias in q_lower:
            conditions.append(_proto_filter(proto.lower()))
            break
    else:
        for proto in VALID_PROTOCOLS:
            if re.search(r"\b" + proto + r"\b", q_lower):
                conditions.append(_proto_filter(proto))
                break

    if not ips:
        dm = DOMAIN_RE.search(q_lower)
        if dm:
            d = dm.group(1)
            conditions.append(
                f'(dns.qry.name contains "{d}" || '
                f'http.host contains "{d}" || '
                f'tls.handshake.extensions_server_name contains "{d}")'
            )

    if conditions:
        return " && ".join(conditions)

    return None


def _proto_filter(proto: str) -> str:
    return f"protocol == {proto.upper()}"


# ---------------------------------------------------------------------------
# Tầng 2: Google Gemini AI
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a network packet filter translator for a custom packet analyzer tool.
Your ONLY task is to convert a user's natural language query (Vietnamese or English)
into a valid filter expression using the syntax described below.

=== SUPPORTED FILTER SYNTAX ===
Comparison operators: ==  !=  >  <  >=  <=
Logical operators: &&  ||
String match: contains "<value>"

Supported fields:
  ip.src == <IPv4>          Source IP
  ip.dst == <IPv4>          Destination IP
  ip.addr == <IPv4>         Either src or dst IP
  tcp.port == <PORT>        TCP src or dst port
  udp.port == <PORT>        UDP src or dst port
  protocol == <PROTO>       Protocol in UPPERCASE (TCP, UDP, HTTP, DNS, TLS, FTP, ICMP, ARP)
  frame.number == <N>       Packet number
  frame.len > <N>           Packet byte length
  tcp.len > 0               TCP packets with payload
  tcp.analysis.flags        TCP error packets (retransmission, dup ACK, etc.)
  tcp.flags.syn == 1        TCP SYN flag
  tcp.flags.ack == 0        TCP ACK flag (0 = not set)
  tcp.flags.reset == 1      TCP RST flag
  tcp.flags.fin == 1        TCP FIN flag
  tcp.window_size == 0      TCP zero window
  tcp.options.sack          TCP SACK option
  ip.ttl < <N>              IP TTL value
  ip.flags.mf == 1          IP fragmented (More Fragments)
  icmp.type == <N>          ICMP type
  icmp.code == <N>          ICMP code
  dns.qry.name contains "<domain>"
  dns.qry.type == 28        DNS AAAA query
  http.host contains "<domain>"
  http.request.method == "POST"
  http.response.code == 404
  tls.handshake.extensions_server_name contains "<domain>"
  http.content_type contains "<type>"
  vlan                      VLAN tagged packets
  eth.dst == ff:ff:ff:ff:ff:ff   Broadcast

=== EXAMPLES ===
"lọc TCP từ 192.168.1.1"                  → ip.src == 192.168.1.1 && protocol == TCP
"gói SYN không có ACK"                    → tcp.flags.syn == 1 && tcp.flags.ack == 0
"lọc gói TTL nhỏ hơn 10"                 → ip.ttl < 10
"tìm gói DHCP Discover hoặc Offer"        → udp.port == 67 || udp.port == 68
"lọc lưu lượng broadcast và multicast"    → eth.dst == ff:ff:ff:ff:ff:ff || ip.dst >= 224.0.0.0
"tìm gói TCP Zero Window"                 → tcp.window_size == 0
"lọc gói có VLAN tag"                     → vlan
"HTTP POST to /login"                     → http.request.method == "POST"
"tìm ảnh"                                 → http.content_type contains "image"
"retransmission"                          → tcp.analysis.flags
"gói từ 10.0.0.1 đến 8.8.8.8"            → ip.src == 10.0.0.1 && ip.dst == 8.8.8.8
"DNS query loại AAAA"                     → dns.qry.type == 28
"frame 500"                               → frame.number == 500

=== RULES ===
- Output ONLY the raw filter string. No markdown, no quotes around the whole output, no explanation.
- Use && to combine multiple conditions, || for alternatives.
- If it cannot be translated meaningfully, output exactly: CANNOT_TRANSLATE

Translate this query: "{query}"
"""


def _parse_filter_text(text: str) -> Optional[str]:
    """Làm sạch và validate text trả về từ AI."""
    cleaned = text.strip().strip("`").strip().split("\n")[0].strip()
    if not cleaned or cleaned == "CANNOT_TRANSLATE":
        return None
    return cleaned


def _is_permanent_error(http_code: int, body: str) -> bool:
    """Kiểm tra xem lỗi có phải vĩnh viễn không (hết quota, key sai, v.v.)"""
    body_lower = body.lower()
    if http_code in (401, 403):
        return True
    if http_code == 429 and any(kw in body_lower for kw in ("quota", "billing", "exceeded")):
        return True
    return False


async def _http_post_json(url: str, headers: dict, payload: dict, timeout: int = 10) -> dict:
    """Helper async HTTP POST."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    loop = asyncio.get_running_loop()

    def _send():
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()

    try:
        raw = await loop.run_in_executor(None, _send)
        return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            pass
        permanent = _is_permanent_error(e.code, err_body)
        raise AIProviderError("HTTP", f"{e.code} {err_body[:120]}", permanent=permanent)
    except Exception as e:
        raise AIProviderError("HTTP", str(e), permanent=False)


async def translate_via_gemini(query: str, api_key: str) -> Optional[str]:
    """
    Gọi Gemini API.
    """
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.5-flash:generateContent?key={api_key}"
    )
    prompt_text = _SYSTEM_PROMPT.replace("{query}", query)
    payload = {
        "contents": [{"parts": [{"text": prompt_text}]}],
        "generationConfig": {"temperature": 0.0, "maxOutputTokens": 256},
    }
    headers = {"Content-Type": "application/json"}

    try:
        res = await _http_post_json(url, headers, payload, timeout=10)
    except AIProviderError as e:
        if e.permanent:
            raise GeminiQuotaExhaustedError("Gemini", e.reason, permanent=True)
        raise AIProviderError("Gemini", e.reason, permanent=False)

    try:
        text = res["candidates"][0]["content"]["parts"][0]["text"]
        return _parse_filter_text(text)
    except (KeyError, IndexError, TypeError):
        return None


# ----------------------------
# Provider Chain Orchestrator
# ----------------------------

async def translate_with_ai_chain(query: str) -> tuple[Optional[str], str]:
    """
    Gọi duy nhất Gemini API làm AI provider.
    Trả về (filter_string, provider_name) hoặc (None, "none").
    """
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not gemini_key:
        print("[ai-chain] Chưa cấu hình GEMINI_API_KEY.")
        return None, "none"

    print("[ai-chain] Thử provider: Gemini")
    try:
        result = await translate_via_gemini(query, gemini_key)
        if result:
            print(f"[ai-chain] ✓ Gemini → {result!r}")
            return result, "Gemini"
        else:
            print("[ai-chain] Gemini trả về None (CANNOT_TRANSLATE).")
    except GeminiQuotaExhaustedError as e:
        print(f"[ai-chain] ✗ Gemini lỗi vĩnh viễn (hết quota/billing): {e.reason}")
        raise e
    except Exception as e:
        print(f"[ai-chain] ✗ Gemini lỗi: {e}")

    return None, "none"


# ---------------------------------------------------------------------------
# Tầng 3: Heuristic Fallback
# ---------------------------------------------------------------------------

def generate_semantic_fallback(query: str) -> str:
    """
    Fallback khi tất cả AI provider đều thất bại.
    Cố gắng tạo ra filter có ý nghĩa nhất có thể.
    """
    q = query.strip().lower()

    # Thử tìm domain name trước
    m = DOMAIN_RE.search(q)
    if m:
        domain = m.group(1)
        return (
            f'dns.qry.name contains "{domain}" || '
            f'http.host contains "{domain}" || '
            f'tls.handshake.extensions_server_name contains "{domain}"'
        )

    # Bóc tách tiền tố hành động
    for prefix in [
        "tìm cho tôi", "tìm kiếm", "tìm gói tin", "lọc gói tin",
        "tìm", "lọc", "hiện", "show", "filter", "find", "search",
        "give me", "get", "display",
    ]:
        if q.startswith(prefix):
            q = q[len(prefix):].strip()
            break

    q_clean = q.replace('"', "").replace("'", "").strip()
    if not q_clean:
        return ""

    return f'contains "{q_clean}"'
