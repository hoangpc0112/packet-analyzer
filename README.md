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

## Presidio & YARA (Clear-text Fields)
- Cài thêm thư viện: `pip install -r requirements.txt`
- Tải model NLP cho Presidio: `python -m spacy download en_core_web_sm`
- Đặt YARA rules trong thư mục `rules/*.yar`
- Bật/tắt bằng biến môi trường:
	- `ENABLE_PRESIDIO=0` hoặc `ENABLE_YARA=0`
	- `PRESIDIO_MIN_SCORE=0.6`, `PRESIDIO_MAX_TEXT_CHARS=4096`
	- `YARA_RULES_DIR=rules`, `YARA_MAX_MATCHES=100`