import os
from pathlib import Path

from secure_transfer_utils import generate_rsa_keypair

PRIVATE_KEY_PATH = Path(os.getenv("SENDER_PRIVATE_KEY", "keys/sender_private.pem"))
PUBLIC_KEY_PATH = Path(os.getenv("SENDER_PUBLIC_KEY", "keys/sender_public.pem"))


def main() -> None:
    generate_rsa_keypair(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
    print(f"[+] Đã tạo khóa riêng của Sender: {PRIVATE_KEY_PATH}")
    print(f"[+] Đã tạo khóa công khai của Sender: {PUBLIC_KEY_PATH}")
    print("[!] Chỉ chia sẻ sender_public.pem cho Receiver để xác minh chữ ký.")
    print("[!] Không commit private key thật lên GitHub.")


if __name__ == "__main__":
    main()
