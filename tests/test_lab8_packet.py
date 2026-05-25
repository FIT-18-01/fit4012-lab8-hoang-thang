import pytest

from secure_transfer_utils import (
    SHA256_DIGEST_SIZE,
    build_secure_packet,
    parse_secure_packet,
    sha256_digest,
)


def test_sha256_digest_has_32_bytes():
    digest = sha256_digest(b"FIT4012 Lab 8")
    assert isinstance(digest, bytes)
    assert len(digest) == SHA256_DIGEST_SIZE


def test_lab8_packet_format_order():
    encrypted_key = b"k" * 256
    ciphertext = b"c" * 24
    digest = b"h" * 32
    signature = b"s" * 256  # RSA 2048-bit signature

    packet = build_secure_packet(encrypted_key, ciphertext, digest, signature)

    # [len_key:4][enc_key:256][len_cipher:4][ciphertext:24][sha256:32][len_sig:4][sig:256]
    # Total: 4+256+4+24+32+4+256 = 580 bytes
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
        build_secure_packet(b"k" * 256, b"c" * 16, b"short", b"s" * 256)


def test_packet_rejects_extra_bytes():
    packet = build_secure_packet(b"k" * 256, b"c" * 16, b"h" * 32, b"s" * 256) + b"extra"
    with pytest.raises(ValueError):
        parse_secure_packet(packet)