import http.server
import socketserver
import base64

PORT = 9000

# Tiny red square PNG image
TINY_PNG = base64.b64decode(
    b"iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAYAAAAeP4ixAAAALElEQVR42u3PMQEAAAgEIDd/2iK4swkKaJe52hEREREREREREREREREREbkxCxg+AW44X178AAAAAElFTkSuQmCC"
)

LOGIN_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>NetScope Local Demo Portal</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a, #1e1b4b);
            color: #f8fafc;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .card {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
            width: 320px;
            text-align: center;
        }
        img {
            margin-bottom: 1rem;
            border-radius: 8px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.3);
        }
        input {
            width: 100%;
            padding: 0.75rem;
            margin: 0.5rem 0;
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.2);
            color: white;
            border-radius: 6px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 0.75rem;
            background: linear-gradient(135deg, #a855f7, #6366f1);
            border: none;
            color: white;
            font-weight: bold;
            border-radius: 6px;
            cursor: pointer;
            margin-top: 1rem;
        }
    </style>
</head>
<body>
    <div class="card">
        <img src="/logo.png" alt="Demo Logo" width="50" height="50">
        <h2>Demo Portal</h2>
        <p>Vui lòng đăng nhập (Chỉ phục vụ demo offline)</p>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Tên đăng nhập / Username" required>
            <input type="password" name="password" placeholder="Mật khẩu / Password" required>
            <button type="submit">Đăng nhập</button>
        </form>
    </div>
</body>
</html>
"""

SUCCESS_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Đăng nhập thành công</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a, #115e59);
            color: #f8fafc;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .card {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 2rem;
            border-radius: 12px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="card">
        <h2> Đăng nhập thành công!</h2>
        <p>Thông tin đã được truyền tải qua HTTP cổng 9000 không mã hóa.</p>
        <p><a href="/login" style="color: #2dd4bf;">Quay lại đăng nhập</a></p>
    </div>
</body>
</html>
"""

class DemoRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(LOGIN_HTML.encode('utf-8'))
        elif self.path == "/logo.png":
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(TINY_PNG)
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        if self.path == "/login":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            print(f"[DEMO_SERVER] Đã nhận POST data: {post_data.decode('utf-8')}")
            
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(SUCCESS_HTML.encode('utf-8'))
        else:
            self.send_error(404, "Not Found")

# Set up server with reuse_address
class MyTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

with MyTCPServer(("", PORT), DemoRequestHandler) as httpd:
    print(f"Máy chủ Demo đang chạy tại http://127.0.0.1:{PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nĐang tắt máy chủ demo...")
