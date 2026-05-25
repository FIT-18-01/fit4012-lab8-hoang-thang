import pytest
from Crypto.PublicKey import RSA

from secure_transfer_utils import (
    decrypt_des_cbc,
    decrypt_des_key_rsa,
    encrypt_des_cbc,
    encrypt_des_key_rsa,
    generate_des_key_iv,
    open_receiver_payload,
    build_sender_payload,
    sha256_digest,
    sign_hash,
    verify_signature,
)


def test_des_cbc_roundtrip():
    plaintext = "Xin chào FIT4012 - truyền dữ liệu an toàn".encode("utf-8")
    des_key, iv = generate_des_key_iv()
    _, _, ciphertext = encrypt_des_cbc(plaintext, des_key, iv)

    assert ciphertext[:8] == iv
    assert decrypt_des_cbc(des_key, ciphertext) == plaintext


def test_des_rejects_wrong_key_size():
    with pytest.raises(ValueError):
        decrypt_des_cbc(b"short", b"12345678" + b"abcdefgh")


def test_rsa_encrypt_decrypt_des_key():
    receiver_key = RSA.generate(2048)
    des_key, _ = generate_des_key_iv()

    encrypted = encrypt_des_key_rsa(des_key, receiver_key.publickey())
    decrypted = decrypt_des_key_rsa(encrypted, receiver_key)

    assert encrypted != des_key
    assert decrypted == des_key


def test_sign_and_verify():
    """Q2: Kiểm tra chữ ký số RSA (PKCS#1 v1.5) hoạt động."""
    sender_key = RSA.generate(2048)
    plaintext = b"Q2 test digital signature"

    digest = sha256_digest(plaintext)
    signature = sign_hash(digest, sender_key)

    # Signature should not be empty
    assert len(signature) > 0
    assert signature != digest

    # Verify with correct public key
    assert verify_signature(digest, signature, sender_key.publickey()) is True

    # Verify with wrong key should fail
    wrong_key = RSA.generate(2048)
    assert verify_signature(digest, signature, wrong_key.publickey()) is False

    # Verify with tampered hash should fail
    tampered_digest = bytes([b ^ 0xFF for b in digest])
    assert verify_signature(tampered_digest, signature, sender_key.publickey()) is False


def test_full_sender_receiver_payload_success():
    receiver_key = RSA.generate(2048)
    sender_key = RSA.generate(2048)
    plaintext = b"Lab 8: DES-CBC + SHA-256 + RSA-OAEP + Digital Signature"

    packet, _des_key, _ciphertext, digest, _signature = build_sender_payload(
        plaintext, receiver_key.publickey(), sender_key
    )
    opened_plaintext, integrity_ok, signature_ok = open_receiver_payload(
        packet, receiver_key, sender_key.publickey()
    )

    assert opened_plaintext == plaintext
    assert integrity_ok is True
    assert signature_ok is True
    assert digest == sha256_digest(plaintext)


def test_tampered_hash_is_detected():
    receiver_key = RSA.generate(2048)
    sender_key = RSA.generate(2048)
    packet, _des_key, _ciphertext, _digest, _signature = build_sender_payload(
        b"original", receiver_key.publickey(), sender_key
    )

    # Packet layout:
    # [len_key:4][enc_key:N][len_cipher:4][ciphertext_with_iv:M][sha256:32][len_sig:4][sig:256]
    # SHA-256 hash is 32 bytes, located before [len_sig:4][sig:256] at the end
    hash_start = len(packet) - 4 - 256 - 32  # skip sig(256) + len_sig(4)

    tampered = bytearray(packet)
    tampered[hash_start] ^= 0xFF  # flip byte in SHA-256 hash
    tampered_packet = bytes(tampered)

    plaintext, integrity_ok, signature_ok = open_receiver_payload(
        tampered_packet, receiver_key, sender_key.publickey()
    )

    assert plaintext == b"original"
    assert integrity_ok is False


def test_tampered_ciphertext_fails_or_changes_integrity():
    receiver_key = RSA.generate(2048)
    sender_key = RSA.generate(2048)
    packet, _des_key, _ciphertext, _digest, _signature = build_sender_payload(
        b"original message", receiver_key.publickey(), sender_key
    )

    # Parse packet to find ciphertext boundaries
    # [len_key:4][enc_key:N][len_cipher:4][ciphertext_with_iv:M][sha256:32][len_sig:4][sig:S]
    enc_key_len = int.from_bytes(packet[0:4], "big")
    cipher_len_offset = 4 + enc_key_len
    cipher_len = int.from_bytes(packet[cipher_len_offset:cipher_len_offset + 4], "big")
    cipher_start = cipher_len_offset + 4
    cipher_end = cipher_start + cipher_len

    # Flip a byte inside ciphertext area (not IV, pick deeper in ciphertext)
    tamper_pos = cipher_start + 9  # byte inside encrypted body, past IV (8 bytes)
    if tamper_pos >= cipher_end:
        tamper_pos = cipher_start + 1

    mutable = bytearray(packet)
    mutable[tamper_pos] ^= 0xFF
    tampered_packet = bytes(mutable)

    try:
        plaintext, integrity_ok, signature_ok = open_receiver_payload(
            tampered_packet, receiver_key, sender_key.publickey()
        )
    except ValueError:
        # DES padding error or parse error -> tampering detected
        return

    # If we get here, integrity should fail
    assert plaintext != b"original message" or integrity_ok is False


def test_signature_with_wrong_sender_key_is_rejected():
    """Q2: Receiver từ chối packet nếu dùng sai sender public key để verify."""
    receiver_key = RSA.generate(2048)
    real_sender_key = RSA.generate(2048)
    wrong_sender_key = RSA.generate(2048)
    plaintext = b"Q2 wrong sender key test"

    packet, _des_key, _ciphertext, _digest, _signature = build_sender_payload(
        plaintext, receiver_key.publickey(), real_sender_key
    )
    opened_plaintext, integrity_ok, signature_ok = open_receiver_payload(
        packet, receiver_key, wrong_sender_key.publickey()
    )

    # Dữ liệu giải mã vẫn đúng nhưng chữ ký phải bị từ chối
    assert opened_plaintext == plaintext
    assert integrity_ok is True
    assert signature_ok is False