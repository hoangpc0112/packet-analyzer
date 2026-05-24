# NetScope / GSATM-VMM — Trình Phân Tích & Giám Sát Gói Tin Mạng Toàn Diện

NetScope (GSATM-VMM) là một ứng dụng web hiện đại, hiệu năng cao giúp thu thập, phân tích gói tin mạng thời gian thực (Live Capture) và hỗ trợ điều tra số (PCAP Triage/Analysis). Ứng dụng tích hợp các tính năng phân tích bảo mật sâu, tự động phát hiện thông tin nhạy cảm rò rỉ, phân tích DNS dị thường và dựng lại dòng thời gian sự cố mạng một cách trực quan.

---

## 🚀 Các Tính Năng Nổi Bật

### 1. Thu Thập Gói Tin Thời Gian Thực (Live Capture)
*   **Bắt gói tin trực tiếp:** Sử dụng thư viện `Scapy` để lắng nghe trên các card mạng đang hoạt động (`ens33`, `lo`, `wlan0`,...).
*   **Bộ lọc hiển thị mạnh mẽ:** Hỗ trợ cú pháp lọc Wireshark cơ bản (ví dụ: `tcp.port == 443`, `ip.src == 192.168.1.1`, `protocol == DNS`) để phân lọc gói tin tức thời.
*   **Phân tích phân tầng (Layer Inspector):** Giải mã chi tiết các giao thức mạng phổ biến: Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, TLS, FTP.

### 2. Tải Lên & Xem Lại PCAP (Offline PCAP Triage)
*   **Upload PCAP/PCAPNG:** Hỗ trợ phân tích ngoại tuyến bằng cách tải lên các file PCAP có sẵn.
*   **Asynchronous Playback:** Đọc file PCAP bằng luồng chạy nền (background thread) và truyền phát gói tin lên giao diện web thông qua **WebSockets** thời gian thực.
*   **Tải về gói tin:** Xuất ngược phiên chụp hiện tại ra file `session.pcap` hoặc tải về chỉ các gói tin được chọn làm bằng chứng mạng (`evidence.pcap`).

### 3. Phân Tích Bảo Mật & Phát Hiện Rò Rỉ Thông Tin (Security & Credentials Audit)
*   **Exposed Credentials Scanner:** Quét và trích xuất tự động thông tin đăng nhập truyền dưới dạng Clear-text (Plaintext) như: `username`, `password`, `api-key`, `jwt`, `token` trong lưu lượng HTTP POST, FTP, hoặc luồng TCP thô.
*   **Auto Decoder Engine:** Tự động giải mã nhiều biến thể dữ liệu nhạy cảm bao gồm URL-encoded, Base64, và giải nén payload của JWT.
*   **Lateral Movement & Suspicious Flows:** Chấm điểm rủi ro (Risk Scoring) và cảnh báo các luồng giao dịch đáng ngờ: chuyển dữ liệu dung lượng lớn ra ngoài (Exfiltration), quét cổng, hoặc kết nối nội bộ bất thường (Lateral Movement qua SMB/RDP/SSH).

### 4. Phân Tích DNS Dị Thường (DNS Anomalies)
*   **Phát hiện DNS Tunneling:** Cảnh báo các domain có độ dài bất thường hoặc các truy vấn DNS NXDOMAIN với tỷ lệ lỗi cao (dấu hiệu của Malware Beaconing hoặc DGA).
*   **Wireshark Filter Generator:** Đề xuất sẵn các bộ lọc Wireshark tương ứng để điều tra nhanh.

### 5. Dựng Luồng TCP (Follow TCP Stream)
*   Tái tạo lại nội dung trao đổi qua lại nguyên bản giữa Client và Server trên một kết nối TCP cụ thể dưới dạng văn bản trực quan.

### 6. Báo Cáo Sự Cố Tự Động (Incident Brief & Narrative Timeline)
*   **Narrative Timeline:** Tự động sắp xếp các sự kiện chính trong phiên chụp mạng theo thứ tự thời gian (ví dụ: khởi tạo luồng kết nối, truy vấn DNS, các phát hiện rò rỉ bảo mật).
*   **Incident Brief Generator:** Tự động tổng hợp và sinh báo cáo sự cố chuẩn bảo mật bằng định dạng Markdown, hỗ trợ sao chép nhanh vào clipboard để báo cáo.

### 7. Giao Diện & Tiện Ích Xuất Dữ Liệu
*   **Giao diện Premium:** Sử dụng phong cách thiết kế hiện đại (Glassmorphism), Dark Mode sang trọng, biểu đồ lưu lượng I/O trực quan thời gian thực bằng `Chart.js`.
*   **Đa dạng định dạng xuất:** Cho phép kết xuất kết quả phân tích mạng ra **JSON, CSV, Text, HTML, hoặc Markdown**.

---

## 🛠️ Công Nghệ Sử Dụng

### Backend (Python 3.10+)
*   **FastAPI:** Cung cấp RESTful API hiệu năng cao và kênh truyền WebSocket siêu tốc.
*   **Scapy:** Thư viện lõi xử lý, phân tích, thu thập và ghi gói tin PCAP.
*   **Uvicorn:** ASGI Web Server để vận hành ứng dụng.
*   **Pydantic:** Xác thực dữ liệu API.

### Frontend
*   **HTML5 & CSS3 (Vanilla):** Giao diện Responsive bóng bẩy, hiệu ứng micro-animations mượt mà, cấu trúc rõ ràng.
*   **JavaScript (ES6):** Xử lý luồng dữ liệu WebSocket, dựng lại chi tiết gói tin và điều phối các sự kiện trên UI.
*   **Chart.js:** Vẽ đồ thị I/O truyền nhận dữ liệu thời gian thực.

---

## 📂 Cấu Trúc Thư Mục Dự Án

```text
packet-analyzer/
├── main.py                # Điểm khởi chạy chính & Logic API, Phân tích (FastAPI + Scapy)
├── requirements.txt       # Danh sách thư viện Python cần thiết
├── README.md              # Tài liệu hướng dẫn gốc
├── README_VN.md           # Hướng dẫn chi tiết bằng Tiếng Việt (Tài liệu này)
├── evidence.pcap          # File PCAP bằng chứng được trích xuất
├── session.pcap           # File PCAP lưu phiên chụp gói tin hiện tại
└── static/                # Thư mục chứa tài nguyên Frontend
    ├── index.html         # Giao diện chính của ứng dụng
    ├── style.css          # Định kiểu phong cách giao diện (Dark Mode & Glassmorphism)
    └── app.js             # Logic Frontend, xử lý API và Websocket
```

---

## 🚀 Hướng Dẫn Cài Đặt và Khởi Chạy (Linux / Ubuntu)

Vì Scapy cần quyền truy cập vào các Socket Raw của hệ thống để bắt gói tin thời gian thực, **bạn phải chạy ứng dụng dưới quyền quản trị (`sudo` / `root`)**.

### Bước 1: Tạo môi trường ảo (Virtual Environment)
Mở Terminal tại thư mục của dự án:
```bash
python3 -m venv .venv
```

### Bước 2: Kích hoạt môi trường ảo
```bash
source .venv/bin/activate
```

### Bước 3: Cài đặt các thư viện phụ thuộc
```bash
pip install -r requirements.txt
```

### Bước 4: Khởi chạy ứng dụng với quyền Sudo
Do môi trường ảo nằm trong thư mục nội bộ của user, bạn cần chỉ định rõ đường dẫn thực thi `uvicorn` của môi trường ảo khi dùng `sudo`:
```bash
sudo .venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --reload --reload-exclude '.venv/*' --reload-exclude '.git/*'
```

*Giải thích các tham số:*
*   `--host 0.0.0.0`: Lắng nghe trên tất cả các địa chỉ IP của máy, cho phép truy cập từ thiết bị khác trong cùng mạng LAN.
*   `--port 8000`: Cổng chạy ứng dụng.
*   `--reload`: Tự động tải lại máy chủ khi có thay đổi mã nguồn.
*   `--reload-exclude`: Bỏ qua việc reload khi các file trong thư mục `.venv` hoặc `.git` thay đổi để tăng hiệu năng.

### Bước 5: Truy cập Giao diện Web
Mở trình duyệt bất kỳ và truy cập địa chỉ:
```text
http://localhost:8000
```
Hoặc truy cập qua IP của máy chủ nếu bạn đang ở thiết bị khác trong mạng LAN:
```text
http://<IP_MÁY_CHỦ>:8000
```

---

## 💡 Hướng Dẫn Sử Dụng Nhanh

1.  **Chụp gói tin Live:**
    *   Tại giao diện **Live Capture**, hãy chọn Card mạng thích hợp (ví dụ: `ens33` hoặc `lo` của bạn) trong menu dropdown bên trái.
    *   Nhấn **Start Capture**. Trình duyệt sẽ nhận dòng chảy gói tin trực tiếp qua WebSocket.
    *   Nhấn vào bất kỳ dòng gói tin nào để xem cấu trúc chi tiết các tầng mạng bên cột **Packet Details** bên phải.
    *   Bấm **Stop** để dừng chụp. Hệ thống sẽ tự động lưu lại phiên làm việc thành `session.pcap` trong thư mục gốc.

2.  **Xem lại File PCAP có sẵn:**
    *   Nhấn nút **Open PCAP** ở góc trên bên phải giao diện.
    *   Chọn file gói tin mạng cần phân tích (ví dụ: `session.pcap` hoặc `evidence.pcap` trong máy bạn).
    *   Hệ thống sẽ thực hiện phát lại và lập chỉ mục các gói tin.

3.  **Thực hiện Phân Tích Chuyên Sâu (Triage & Security Audit):**
    *   Sau khi đã có gói tin (qua Live Capture hoặc Open PCAP), bấm nút **Run Analysis** ở góc trên cùng bên phải.
    *   Chuyển qua các tab:
        *   **Overview:** Xem biểu đồ băng thông, thống kê tổng quát (KPIs) và các luồng hội thoại mạng lớn nhất.
        *   **Security & Alerts:** Xem danh sách mật khẩu, tài khoản rò rỉ (Clear-text), các luồng đáng ngờ, và bấm nút **Generate Incident Brief** để nhận báo cáo sự cố dạng Markdown.
        *   **DNS Analysis:** Theo dõi hoạt động phân giải tên miền bất thường.
        *   **Narrative Timeline:** Đọc lịch sử câu chuyện mạng một cách trực quan.
