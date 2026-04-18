# Hướng dẫn
## Cài Python 3.10+
Mở terminal tại thư mục dự án, tạo và kích hoạt môi trường ảo
```
python -m venv .venv
..venv\Scripts\Activate.ps1
```
hoặc
```
python -m venv .venv
.venv\Scripts\activate.bat
```

## Cài thư viện:
```
pip install -r requirements.txt
```

## Chạy project:
```
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```