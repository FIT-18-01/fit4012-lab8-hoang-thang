import os
import socket
import time
from pathlib import Path

from secure_transfer_utils import build_sender_payload, load_public_key, load_private_key, parse_secure_packet

SERVER_IP = os.getenv("SERVER_IP", "192.168.61.177")
DATA_PORT = int(os.getenv("DATA_PORT", os.getenv("PORT", "6000")))
RECEIVER_PUBLIC_KEY = os.getenv("RECEIVER_PUBLIC_KEY", "keys/receiver_public.pem")
SENDER_PRIVATE_KEY = os.getenv("SENDER_PRIVATE_KEY", "keys/sender_private.pem")
MESSAGE_ENV = os.getenv("MESSAGE")
INPUT_FILE = os.getenv("INPUT_FILE", "")
LOG_FILE = os.getenv("SENDER_LOG_FILE", "")
TIMEOUT = float(os.getenv("SOCKET_TIMEOUT", "10"))
CONNECT_RETRIES = int(os.getenv("CONNECT_RETRIES", "5"))
CONNECT_RETRY_DELAY = float(os.getenv("CONNECT_RETRY_DELAY", "2"))


def get_plaintext() -> bytes:
    """Read plaintext from INPUT_FILE, MESSAGE env var, or keyboard input."""
    if INPUT_FILE:
        return Path(INPUT_FILE).read_bytes()
    if MESSAGE_ENV is not None:
        return MESSAGE_ENV.encode("utf-8")
    return input("Nhập bản tin: ").encode("utf-8")


def send_packet(host: str, port: int, packet: bytes) -> None:
    """Open one TCP connection and send all bytes. Retries on ConnectionRefusedError."""
    last_error = None
    for attempt in range(1, CONNECT_RETRIES + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(None)
                sock.connect((host, port))
                sock.sendall(packet)
            return
        except ConnectionRefusedError as e:
            last_error = e
            print(f"[!] Kết nối bị từ chối (lần {attempt}/{CONNECT_RETRIES}). "
                  f"Thử lại sau {CONNECT_RETRY_DELAY}s ...")
            time.sleep(CONNECT_RETRY_DELAY)
        except (socket.timeout, OSError) as e:
            raise ConnectionError(f"Không thể kết nối đến {host}:{port} - {e}") from e

    raise ConnectionError(
        f"Không thể kết nối đến {host}:{port} sau {CONNECT_RETRIES} lần thử. "
        f"Lỗi cuối: {last_error}"
    )


def main() -> None:
    plaintext = get_plaintext()
    receiver_public_key = load_public_key(RECEIVER_PUBLIC_KEY)
    sender_private_key = load_private_key(SENDER_PRIVATE_KEY)

    packet, des_key, ciphertext_with_iv, plaintext_hash, signature = build_sender_payload(
        plaintext, receiver_public_key, sender_private_key
    )
    encrypted_des_key, _, _, _ = parse_secure_packet(packet)

    print(f"[*] Đang kết nối đến Receiver tại {SERVER_IP}:{DATA_PORT} ...")
    send_packet(SERVER_IP, DATA_PORT, packet)

    lines = [
        "[+] Đã tính SHA-256 của bản tin gốc.",
        "[+] Đã sinh DES key và IV ngẫu nhiên.",
        "[+] Đã mã hóa bản tin bằng DES-CBC.",
        "[+] Đã mã hóa DES key bằng RSA public key của receiver.",
        "[+] Đã ký SHA-256 hash bằng RSA private key của sender.",
        "[+] Đã gửi gói dữ liệu an toàn qua socket.",
        f"Server: {SERVER_IP}",
        f"Data port: {DATA_PORT}",
        f"Receiver public key: {RECEIVER_PUBLIC_KEY}",
        f"Sender private key: {SENDER_PRIVATE_KEY}",
        f"Plaintext length: {len(plaintext)} bytes",
        f"DES key length: {len(des_key)} bytes",
        f"Encrypted DES key length: {len(encrypted_des_key)} bytes",
        f"Ciphertext length including IV: {len(ciphertext_with_iv)} bytes",
        f"SHA-256: {plaintext_hash.hex()}",
        f"Signature length: {len(signature)} bytes",
    ]

    for line in lines:
        print(line)

    if LOG_FILE:
        Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
        Path(LOG_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
