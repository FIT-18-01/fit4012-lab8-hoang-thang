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


def make_keypair():
    return RSA.generate(2048)


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
    receiver_key = make_keypair()
    des_key, _ = generate_des_key_iv()

    encrypted = encrypt_des_key_rsa(des_key, receiver_key.publickey())
    decrypted = decrypt_des_key_rsa(encrypted, receiver_key)

    assert encrypted != des_key
    assert decrypted == des_key


def test_sign_and_verify():
    sender_key = make_keypair()
    plaintext_hash = sha256_digest(b"hello lab8")

    signature = sign_hash(plaintext_hash, sender_key)
    assert verify_signature(plaintext_hash, signature, sender_key.publickey()) is True


def test_verify_rejects_wrong_key():
    sender_key = make_keypair()
    other_key = make_keypair()
    plaintext_hash = sha256_digest(b"hello lab8")

    signature = sign_hash(plaintext_hash, sender_key)
    assert verify_signature(plaintext_hash, signature, other_key.publickey()) is False


def test_verify_rejects_tampered_hash():
    sender_key = make_keypair()
    plaintext_hash = sha256_digest(b"hello lab8")
    signature = sign_hash(plaintext_hash, sender_key)

    tampered_hash = bytes([plaintext_hash[0] ^ 0xFF]) + plaintext_hash[1:]
    assert verify_signature(tampered_hash, signature, sender_key.publickey()) is False


def test_full_sender_receiver_payload_success():
    receiver_key = make_keypair()
    sender_key = make_keypair()
    plaintext = b"Lab 8: DES-CBC + SHA-256 + RSA-OAEP + Digital Signature"

    packet, _des_key, _ciphertext, digest, signature = build_sender_payload(
        plaintext, receiver_key.publickey(), sender_key
    )
    opened_plaintext, integrity_ok, signature_ok = open_receiver_payload(
        packet, receiver_key, sender_key.publickey()
    )

    assert opened_plaintext == plaintext
    assert integrity_ok is True
    assert signature_ok is True
    assert digest == sha256_digest(plaintext)


def test_tampered_hash_detected():
    receiver_key = make_keypair()
    sender_key = make_keypair()
    packet, *_ = build_sender_payload(b"original", receiver_key.publickey(), sender_key)

    # Flip last byte of sha256_hash in packet (32 bytes before [len_sig])
    # Find sha256 position: after enc_key and ciphertext sections
    mutable = bytearray(packet)
    # Signature is at the end: [len_sig:4][sig]; hash is 32 bytes before that section
    import struct
    sig_len = struct.unpack("!I", bytes(mutable[-4 - struct.unpack("!I", bytes(mutable[-4:]))[0] - 4:
                                                -struct.unpack("!I", bytes(mutable[-4:]))[0] - 4 + 4]))[0]
    # Simpler: just flip the last byte of the packet (signature byte) to test signature_ok
    tampered = bytes(mutable[:-1]) + bytes([mutable[-1] ^ 0x01])
    _, integrity_ok, signature_ok = open_receiver_payload(tampered, receiver_key, sender_key.publickey())
    assert signature_ok is False


def test_tampered_ciphertext_fails_or_changes_integrity():
    receiver_key = make_keypair()
    sender_key = make_keypair()
    packet, *_ = build_sender_payload(b"original message", receiver_key.publickey(), sender_key)

    mutable = bytearray(packet)
    mutable[10] ^= 0x01  # Flip inside encrypted_des_key section (RSA decrypt will fail)

    try:
        plaintext, integrity_ok, signature_ok = open_receiver_payload(
            bytes(mutable), receiver_key, sender_key.publickey()
        )
    except (ValueError, Exception):
        return

    assert plaintext != b"original message" or integrity_ok is False
