import pytest

from secure_transfer_utils import (
    SHA256_DIGEST_SIZE,
    build_secure_packet,
    parse_secure_packet,
    sha256_digest,
)

# Signature placeholder dùng trong test packet (không cần RSA thật)
FAKE_SIG = b"s" * 256


def test_sha256_digest_has_32_bytes():
    digest = sha256_digest(b"FIT4012 Lab 8")
    assert isinstance(digest, bytes)
    assert len(digest) == SHA256_DIGEST_SIZE


def test_lab8_packet_format_order():
    encrypted_key = b"k" * 256
    ciphertext = b"c" * 24
    digest = b"h" * 32
    signature = b"s" * 256

    packet = build_secure_packet(encrypted_key, ciphertext, digest, signature)

    # [len_key:4=256][key:256][len_cipher:4=24][cipher:24][hash:32][len_sig:4=256][sig:256]
    assert packet[:4] == (256).to_bytes(4, "big")
    assert packet[4:260] == encrypted_key
    assert packet[260:264] == (24).to_bytes(4, "big")
    assert packet[264:288] == ciphertext
    assert packet[288:320] == digest
    assert packet[320:324] == (256).to_bytes(4, "big")
    assert packet[324:580] == signature

    parsed_key, parsed_ciphertext, parsed_digest, parsed_sig = parse_secure_packet(packet)
    assert parsed_key == encrypted_key
    assert parsed_ciphertext == ciphertext
    assert parsed_digest == digest
    assert parsed_sig == signature


def test_packet_rejects_wrong_hash_size():
    with pytest.raises(ValueError):
        build_secure_packet(b"k" * 256, b"c" * 16, b"short", FAKE_SIG)


def test_packet_rejects_empty_signature():
    with pytest.raises(ValueError):
        build_secure_packet(b"k" * 256, b"c" * 16, b"h" * 32, b"")


def test_packet_rejects_extra_bytes():
    packet = build_secure_packet(b"k" * 256, b"c" * 16, b"h" * 32, FAKE_SIG) + b"extra"
    with pytest.raises(ValueError):
        parse_secure_packet(packet)
