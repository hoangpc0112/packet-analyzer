import re
import os
import json
import asyncio
import urllib.request
from typing import Optional
from pydantic import BaseModel

class TranslateFilterRequest(BaseModel):
    query: str

def translate_local_rules(query: str) -> Optional[str]:
    """
    Biên dịch cục bộ cho các câu truy vấn đơn giản, hiển nhiên không cần đến AI:
    - Địa chỉ IP (IPv4) và hướng (từ/đến).
    - Số cổng (port) và hướng/giao thức.
    - Số thứ tự gói tin (frame number).
    - Tên giao thức viết tắt chuẩn (TCP, UDP, HTTP, DNS, ICMP...).
    - Hoặc nếu bản thân câu truy vấn đã là cú pháp Wireshark hợp lệ.
    """
    q = query.lower().strip()
    if not q:
        return None

    # 0. Phát hiện bộ lọc độ dài gói tin vật lý (ví dụ: "độ dài > 1000", "độ dài lớn hơn 500", "len < 100")
    len_match_gt = re.search(r'(?:độ dài|kích thước|len|length)\s*(?:lớn hơn|trên|vượt quá|>)\s*([0-9]+)', q)
    if len_match_gt:
        return f"frame.len > {len_match_gt.group(1)}"
        
    len_match_lt = re.search(r'(?:độ dài|kích thước|len|length)\s*(?:nhỏ hơn|dưới|<)\s*([0-9]+)', q)
    if len_match_lt:
        return f"frame.len < {len_match_lt.group(1)}"
        
    len_match_eq = re.search(r'(?:độ dài|kích thước|len|length)\s*(?:bằng|==)\s*([0-9]+)', q)
    if len_match_eq:
        return f"frame.len == {len_match_eq.group(1)}"

    # Nếu câu lệnh chứa các từ khóa chỉ ngữ cảnh phức tạp (tải, gửi, nhận, file, mật khẩu, lỗi, trùng, mất...), nhường hoàn toàn cho AI
    complex_words = [
        "tải", "file", "gửi", "nhận", "mật khẩu", "password", "lỗi", "error", 
        "thành công", "thất bại", "dữ liệu", "data", "nội dung", "giao tiếp", 
        "kết nối", "trùng", "mất", "chậm", "nhanh", "ảnh", "png", "jpg", "jpeg", 
        "payload", "len", "length", "kích thước", "dung lượng", "độ dài"
    ]
    if any(w in q for w in complex_words):
        return None

    # Nếu bản thân câu truy vấn đã là cú pháp Wireshark Display Filter chuẩn, giữ nguyên
    wireshark_operators = ["==", "!=", ">", "<", ">=", "<=", "&&", "||", "contains", "matches"]
    if any(op in q for op in wireshark_operators):
        return query.strip()

    # Nếu chỉ gõ đúng tên giao thức chuẩn
    valid_protocols = {"tcp", "udp", "http", "dns", "icmp", "tls", "ftp", "arp", "ip", "ipv6"}
    if q in valid_protocols:
        return q.upper()

    # 1. Phát hiện số thứ tự gói tin (ví dụ: "gói tin số 500", "gói 45", "frame 123")
    frame_match = re.search(r'(?:gói tin số|gói số|gói|frame)\s*([0-9]+)', q)
    if frame_match:
        return f"frame.number == {frame_match.group(1)}"

    # 2. Sử dụng Regex trích xuất địa chỉ IP (IPv4)
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ipv4_pattern, q)

    # 3. Sử dụng Regex trích xuất số Cổng (Port)
    port_pattern = r'(?:port|cổng|cổng\s+số)\s*([0-9]+)'
    ports = re.findall(port_pattern, q)
    if not ports:
        # Tự động bắt các số đứng độc lập có độ dài 2-5 chữ số (không thuộc IP segment)
        standalone_nums = re.findall(r'\b([0-9]{2,5})\b', q)
        ip_segments = set()
        for ip in ips:
            ip_segments.update(ip.split('.'))
        for num in standalone_nums:
            if num not in ip_segments:
                val = int(num)
                if 1 <= val <= 65535 and val not in [int(x) for x in ports]:
                    ports.append(num)

    # 4. Nhận diện các Giao thức cơ bản
    protocols = []
    for proto in valid_protocols:
        if re.search(r'\b' + proto + r'\b', q) or (proto == "dns" and "tên miền" in q) or (proto == "http" and "web" in q):
            protocols.append(proto.upper())

    conditions = []
    
    # 5. Phân tích hướng của IP dựa trên ngữ cảnh ("từ" -> src, "đến" -> dst)
    if ips:
        for ip in ips:
            ip_idx = q.find(ip)
            preceding_text = q[max(0, ip_idx-20):ip_idx]
            if any(w in preceding_text for w in ["từ", "from", "src", "source"]):
                conditions.append(f"ip.src == {ip}")
            elif any(w in preceding_text for w in ["đến", "tới", "to", "dst", "destination"]):
                conditions.append(f"ip.dst == {ip}")
            else:
                conditions.append(f"ip.addr == {ip}")

    if ports:
        port_proto = "udp" if "udp" in q else "tcp"
        for port in ports:
            conditions.append(f"{port_proto}.port == {port}")

    if protocols:
        for proto in protocols:
            if proto not in ["IP"]:
                conditions.append(f"protocol == {proto}")

    # Kết hợp toàn bộ các điều kiện tìm thấy bằng toán tử "&&"
    if conditions:
        return " && ".join(conditions)

    return None

async def translate_via_gemini(query: str, api_key: str) -> Optional[str]:
    """
    Gửi truy vấn đến Gemini API khi không có Local Rule nào khớp.
    """
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    
    prompt = f"""You are a professional network administrator and translation assistant for a packet analyzer.
Translate the user's natural language query (Vietnamese or English) into a valid Wireshark Display Filter string.

Supported syntax and patterns:
- ip.src == <IP> (e.g. ip.src == 192.168.1.1)
- ip.dst == <IP> (e.g. ip.dst == 8.8.8.8)
- ip.addr == <IP> (e.g. ip.addr == 192.168.1.100)
- tcp.port == <PORT> (e.g. tcp.port == 80)
- udp.port == <PORT> (e.g. udp.port == 53)
- protocol == <PROTO> (e.g. protocol == TCP, protocol == HTTP, protocol == DNS, protocol == TLS)
- dns.qry.name contains "<domain>" (e.g. dns.qry.name contains "google.com")
- tls.handshake.extensions_server_name contains "<domain>" (e.g. tls.handshake.extensions_server_name contains "google.com")
- http.host contains "<domain>" (e.g. http.host contains "google.com")
- http.content_type contains "<type>" (e.g. http.content_type contains "image", http.content_type contains "png", http.content_type contains "jpeg")
- frame.number == <NUM> (e.g. frame.number == 100)
- frame.len > <NUM> (e.g. frame.len > 1000 for packets with physical length greater than 1000 bytes)
- tcp.len > 0 (e.g. tcp.len > 0 for TCP packets with payload)
- tcp.analysis.flags (e.g. tcp.analysis.flags for TCP packets with error/analysis issues like retransmissions, duplicate ACKs, zero window, etc.)
- Generic content search: contains "<text>" (e.g. contains "password")
- Combining with logical operators: && (AND), || (OR)

Examples:
- "lọc các gói tin giao tiếp với google" -> dns.qry.name contains "google" || http.host contains "google" || tls.handshake.extensions_server_name contains "google"
- "Tìm các gói tin TCP từ IP 192.168.1.100" -> ip.src == 192.168.1.100 && protocol == TCP
- "tìm gói tin dns đến google.com" -> dns.qry.name contains "google.com"
- "Tìm các gói tin chứa ảnh" -> http.content_type contains "image"
- "tìm các gói tin tcp có payload" -> tcp.len > 0
- "tìm các gói tin độ dài > 1000" -> frame.len > 1000
- "tìm các gói tin có độ dài > 500 bị lỗi" -> frame.len > 500 && tcp.analysis.flags

Translate this query: "{query}"

Output ONLY the raw Wireshark display filter string. Do NOT write markdown, do NOT wrap in quotes, do NOT explain anything. If it cannot be translated, output "".
"""

    data = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": 0.0,
            "maxOutputTokens": 128
        }
    }
    
    req_body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=req_body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    
    loop = asyncio.get_running_loop()
    def send_request():
        with urllib.request.urlopen(req, timeout=8) as response:
            return response.read()
            
    res_bytes = await loop.run_in_executor(None, send_request)
    res_json = json.loads(res_bytes.decode("utf-8"))
    
    candidates = res_json.get("candidates", [])
    if candidates:
        parts = candidates[0].get("content", {}).get("parts", [])
        if parts:
            result = parts[0].get("text", "").strip()
            result = result.replace("`", "").strip()
            return result
            
    return None

def generate_semantic_fallback(query: str) -> str:
    """
    Bộ biên dịch ngữ nghĩa thô dự phòng khi không khớp local rule và AI tắt/lỗi.
    """
    q = query.lower().strip()
    
    # Bóc tách nếu đã có contains bao bọc sẵn từ lần chạy trước để tránh lặp lồng nhau
    while q.startswith('contains "') and q.endswith('"'):
        q = q[10:-1].strip()
        
    domain_match = re.search(r'\b([a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)\b', q)
    if domain_match:
        return f'dns.qry.name contains "{domain_match.group(1)}"'
        
    for prefix in ["tìm cho tôi", "tìm gói tin", "tìm", "lọc", "hiện", "show", "filter", "find"]:
        if q.startswith(prefix):
            q = q[len(prefix):].strip()
            
    clean_q = q.replace('"', '').replace("'", "").strip()
    return f'contains "{clean_q}"'
