[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/lnmamCNz)
# FIT4012 - Lab 8 - Xây dựng ứng dụng truyền dữ liệu an toàn

Repo này triển khai chương trình truyền dữ liệu an toàn qua **TCP socket** bằng mô hình lai:

1. **DES-CBC** để mã hóa bản tin.
2. **SHA-256** để kiểm tra tính toàn vẹn của bản tin gốc.
3. **RSA-OAEP** để mã hóa khóa DES trước khi gửi qua mạng.
4. **Chữ ký số RSA (PKCS#1 v1.5)** để xác thực danh tính Sender.

> **Lưu ý quan trọng**: DES hiện không còn an toàn cho hệ thống thật vì kích thước khóa nhỏ. Repo này dùng DES theo đúng yêu cầu bài thực hành để hiểu cơ chế mã hóa lai, kiểm tra toàn vẹn và bảo vệ khóa đối xứng.

---

## Team members

- **Thành viên 1**: Nguyễn Việt Hoàng - MSSV: 1871020253
- **Thành viên 2**: Mạc Đức Thắng - MSSV: 1871020530

## Task division

- **Thành viên 1 phụ trách chính**: `secure_transfer_utils.py`, `keygen.py`, `keygen_sender.py`, `tests/`
- **Thành viên 2 phụ trách chính**: `sender.py`, `receiver.py`, viết báo cáo, threat model
- **Phần làm chung**: Debug, demo, README, câu hỏi mở rộng

## Demo roles

- **Demo Sender / mã hóa / ký số / log gửi**: Nguyễn Việt Hoàng
- **Demo Receiver / giải mã / kiểm tra hash + chữ ký**: Mạc Đức Thắng
- **Cả hai cùng trả lời câu hỏi mở rộng AES và chữ ký số**: Nguyễn Việt Hoàng & Mạc Đức Thắng

---

## Mục tiêu học tập

Sau bài lab này, sinh viên có thể:

- Mô tả được luồng truyền dữ liệu an toàn giữa Sender và Receiver qua TCP socket.
- Cài đặt được DES-CBC với key, IV và PKCS#7 padding.
- Tính và kiểm tra được SHA-256 để phát hiện dữ liệu bị thay đổi.
- Sử dụng RSA-OAEP để mã hóa khóa DES trước khi truyền.
- Ký và xác minh chữ ký số RSA để xác thực danh tính Sender.
- Thiết kế được packet có header độ dài cho dữ liệu nhị phân.
- Viết test cho các tình huống đúng, sai định dạng, sai hash và dữ liệu bị can thiệp.

---

## Cấu trúc repo

```text
.
├── secure_transfer_utils.py   # Thư viện DES, RSA, SHA-256, chữ ký số, packet
├── keygen.py                  # Sinh cặp khóa RSA cho Receiver
├── keygen_sender.py           # Sinh cặp khóa RSA cho Sender (dùng để ký)
├── sender.py                  # Chương trình Sender
├── receiver.py                # Chương trình Receiver
├── requirements.txt
├── sample_input.txt
├── sample_output.txt
├── report-1page.md
├── threat-model-1page.md
├── peer-review-response.md
├── logs/
├── keys/
└── tests/
    ├── test_lab8_crypto.py
    ├── test_lab8_packet.py
    └── test_lab8_socket_helpers.py
```

---

## Protocol truyền dữ liệu

Sender gửi **một gói dữ liệu nhị phân** qua socket theo thứ tự:

```text
[len_key: 4 bytes]
[encrypted_des_key: N bytes]
[len_cipher: 4 bytes]
[ciphertext: M bytes, gồm IV 8 byte ở đầu]
[sha256_hash: 32 bytes]
[len_sig: 4 bytes]
[signature: S bytes]
```

| Trường | Ý nghĩa |
|---|---|
| `len_key` | Độ dài DES key đã mã hóa bằng RSA, lưu bằng 4 byte network byte order |
| `encrypted_des_key` | DES key 8 byte sau khi mã hóa bằng RSA public key của Receiver |
| `len_cipher` | Độ dài ciphertext, bao gồm IV ở 8 byte đầu |
| `ciphertext` | `IV + DES_CBC(PKCS7(plaintext))` |
| `sha256_hash` | SHA-256 của plaintext gốc, dài 32 byte |
| `len_sig` | Độ dài chữ ký RSA, lưu bằng 4 byte |
| `signature` | Chữ ký RSA PKCS#1 v1.5 của Sender ký lên `sha256_hash` |

**Luồng bảo mật:**
- `encrypted_des_key` → chỉ Receiver (có private key) mới giải mã được DES key.
- `sha256_hash` → Receiver kiểm tra plaintext có bị thay đổi không.
- `signature` → Receiver xác minh bản tin đúng là từ Sender (có private key của Sender).

---

## Cài đặt môi trường

```bash
python -m venv .venv
source .venv/bin/activate     # Linux/macOS
# hoặc: .venv\Scripts\Activate.ps1   (Windows PowerShell)
pip install -r requirements.txt
```

---

## Bước 1 - Tạo khóa RSA

### Trên máy Receiver - tạo khóa Receiver:

```bash
python keygen.py
# Tạo: keys/receiver_private.pem  keys/receiver_public.pem
```

### Trên máy Sender - tạo khóa Sender:

```bash
python keygen_sender.py
# Tạo: keys/sender_private.pem  keys/sender_public.pem
```

**Trao đổi public key giữa 2 máy:**

| File | Từ | Gửi đến |
|---|---|---|
| `receiver_public.pem` | Máy Receiver | Máy Sender |
| `sender_public.pem` | Máy Sender | Máy Receiver |

---

## Demo LOCAL (1 máy, 2 terminal)

```bash
# Tạo đủ 2 cặp khóa
python keygen.py
python keygen_sender.py
```

**Terminal 1 - Receiver:**

```bash
RECEIVER_HOST=192.168.61.177 \
DATA_PORT=6000 \
RECEIVER_PRIVATE_KEY=keys/receiver_private.pem \
SENDER_PUBLIC_KEY=keys/sender_public.pem \
RECEIVER_LOG_FILE=logs/receiver_success.log \
OUTPUT_FILE=sample_output.txt \
python receiver.py
```

**Terminal 2 - Sender:**

```bash
SERVER_IP=192.168.61.177 \
DATA_PORT=6000 \
RECEIVER_PUBLIC_KEY=keys/receiver_public.pem \
SENDER_PRIVATE_KEY=keys/sender_private.pem \
MESSAGE="Xin chao FIT4012 - Lab 8 Secure Transfer" \
SENDER_LOG_FILE=logs/sender_success.log \
python sender.py
```

---

## Demo 2 MÁY KHÁC NHAU (LAN)

```
[Máy Sender]  IP: 192.168.x.A          [Máy Receiver]  IP: 192.168.x.B
sender.py ──────── TCP port 6000 ──────► receiver.py
  (có receiver_public.pem)                (có sender_public.pem)
  (có sender_private.pem)                 (có receiver_private.pem)
```

### Bước 1 - Mỗi máy tạo khóa của mình

M�y Receiver:
```bash
python keygen.py
# → keys/receiver_private.pem  keys/receiver_public.pem
```

M�y Sender:
```bash
python keygen_sender.py
# → keys/sender_private.pem  keys/sender_public.pem
```

### Bước 2 - Trao đổi public key

```bash
# Chạy trên máy Sender: lấy public key của Receiver
scp user@192.168.x.B:/path/to/project/keys/receiver_public.pem ./keys/

# Chạy trên máy Receiver: lấy public key của Sender
scp user@192.168.x.A:/path/to/project/keys/sender_public.pem ./keys/
```

Hoặc copy qua USB, chia sẻ file mạng nội bộ.

> **Quan trọng**: Chỉ trao đổi file `*_public.pem`. Không chia sẻ `*_private.pem`.

### Bước 3 - Mở firewall trên máy Receiver

**Linux:** `sudo ufw allow 6000/tcp`

**Windows (Admin PowerShell):** `New-NetFirewallRule -DisplayName "Lab8" -Direction Inbound -Protocol TCP -LocalPort 6000 -Action Allow`

### Bước 4 - Chạy Receiver

```bash
DATA_PORT=6000 \
RECEIVER_PRIVATE_KEY=keys/receiver_private.pem \
SENDER_PUBLIC_KEY=keys/sender_public.pem \
RECEIVER_LOG_FILE=logs/receiver_success.log \
OUTPUT_FILE=sample_output.txt \
python receiver.py
```

### Bước 5 - Chạy Sender

```bash
SERVER_IP=192.168.x.B \
DATA_PORT=6000 \
RECEIVER_PUBLIC_KEY=keys/receiver_public.pem \
SENDER_PRIVATE_KEY=keys/sender_private.pem \
MESSAGE="Xin chao FIT4012 - Lab 8 LAN Demo" \
SENDER_LOG_FILE=logs/sender_success.log \
python sender.py
```

**Output mong đợi - Receiver:**

```
[*] Receiver đang lắng nghe tại 0.0.0.0:6000
[+] Đã nhận kết nối từ 192.168.x.A:XXXX
[+] Tính toàn vẹn: SHA-256 khớp.
[+] Xác thực Sender: Chữ ký RSA hợp lệ - đúng là Sender đã gửi.
[+] Đã giải mã DES key bằng RSA private key của receiver.
[+] Đã giải mã bản tin bằng DES-CBC.
[+] Bản tin gốc: Xin chao FIT4012 - Lab 8 LAN Demo
```

---

## Gửi dữ liệu từ file

```bash
# Receiver
DATA_PORT=6000 \
RECEIVER_PRIVATE_KEY=keys/receiver_private.pem \
SENDER_PUBLIC_KEY=keys/sender_public.pem \
OUTPUT_FILE=sample_output.txt \
python receiver.py

# Sender
SERVER_IP=192.168.x.B \
DATA_PORT=6000 \
RECEIVER_PUBLIC_KEY=keys/receiver_public.pem \
SENDER_PRIVATE_KEY=keys/sender_private.pem \
INPUT_FILE=sample_input.txt \
python sender.py
```

---

## Biến môi trường đầy đủ

### Sender

| Biến | Mặc định | Mô tả |
|---|---|---|
| `SERVER_IP` | `192.168.61.177` | IP của máy Receiver |
| `DATA_PORT` | `6000` | Cổng TCP |
| `RECEIVER_PUBLIC_KEY` | `keys/receiver_public.pem` | Public key của Receiver (mã hóa DES key) |
| `SENDER_PRIVATE_KEY` | `keys/sender_private.pem` | Private key của Sender (ký chữ ký số) |
| `MESSAGE` | (trống) | Bản tin gửi trực tiếp |
| `INPUT_FILE` | (trống) | Đọc bản tin từ file |
| `SENDER_LOG_FILE` | (trống) | Ghi log ra file |
| `SOCKET_TIMEOUT` | `10` | Timeout kết nối (giây) |
| `CONNECT_RETRIES` | `5` | Số lần retry khi bị từ chối |
| `CONNECT_RETRY_DELAY` | `2` | Giây chờ giữa các lần retry |

### Receiver

| Biến | Mặc định | Mô tả |
|---|---|---|
| `RECEIVER_HOST` | `192.168.61.177` | IP lắng nghe |
| `DATA_PORT` | `6000` | Cổng TCP |
| `RECEIVER_PRIVATE_KEY` | `keys/receiver_private.pem` | Private key của Receiver (giải mã DES key) |
| `SENDER_PUBLIC_KEY` | `keys/sender_public.pem` | Public key của Sender (xác minh chữ ký) |
| `OUTPUT_FILE` | (trống) | Ghi plaintext ra file |
| `RECEIVER_LOG_FILE` | (trống) | Ghi log ra file |
| `SOCKET_TIMEOUT` | `10` | Timeout chờ dữ liệu (giây) |

---

## Xử lý lỗi thường gặp

| Lỗi | Nguyên nhân | Cách xử lý |
|---|---|---|
| `ConnectionRefusedError` | Receiver chưa chạy | Chạy Receiver trước, Sender tự retry 5 lần |
| `FileNotFoundError: receiver_public.pem` | Chưa trao đổi public key | Copy file đúng vào thư mục `keys/` |
| `FileNotFoundError: sender_public.pem` | Receiver chưa có public key của Sender | Copy `sender_public.pem` sang máy Receiver |
| `Chữ ký RSA KHÔNG hợp lệ` | Dùng nhầm public key hoặc packet bị giả mạo | Kiểm tra đúng `sender_public.pem` |
| `socket.timeout` | Timeout | Tăng `SOCKET_TIMEOUT=30` cả 2 máy |

---

## Chạy test

```bash
pytest -q
```

---

## Câu hỏi mở rộng

### Q1. Thay DES bằng AES

- **AES-128**: key 16 byte. **AES-256**: key 32 byte.
- **AES-CBC**: IV 16 byte.
- **AES-GCM** kết hợp mã hóa và xác thực dữ liệu (AEAD) trong một bước, không cần tính hash riêng như CBC + SHA-256. GCM dùng tag 16 byte đảm bảo cả confidentiality và integrity/authenticity đồng thời, tránh lỗi thứ tự "encrypt-then-MAC".

### Q2. Chữ ký số (đã triển khai)

Phiên bản này đã tích hợp chữ ký số:

- Sender có cặp khóa RSA riêng (`sender_private.pem` / `sender_public.pem`).
- Sender ký lên SHA-256 hash của plaintext bằng `sender_private.pem`.
- Receiver xác minh chữ ký bằng `sender_public.pem`.
- Nếu verify thành công → Receiver có bằng chứng bản tin đúng là từ Sender.

---

## Ethics & Safe use

- Chỉ chạy demo trên máy cá nhân, VM hoặc mạng nội bộ phục vụ học tập.
- Không quét cổng hoặc thử nghiệm trên hệ thống không được phép.
- Không dùng dữ liệu cá nhân thật hoặc dữ liệu nhạy cảm để demo.
- Không commit private key thật lên GitHub.
- Không trình bày hệ thống DES-CBC này như một giải pháp an toàn sẵn sàng triển khai.

---

## Bài học chính

```text
DES-CBC         → che nội dung bản tin
SHA-256         → kiểm tra dữ liệu có bị thay đổi không
RSA-OAEP        → bảo vệ khóa DES khi truyền qua mạng
Chữ ký số RSA   → xác thực danh tính Sender
```
