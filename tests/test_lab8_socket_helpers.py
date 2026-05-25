import socket
import threading

from secure_transfer_utils import build_secure_packet, recv_secure_packet


def test_recv_secure_packet_over_local_socket():
    packet = build_secure_packet(b"k" * 256, b"c" * 24, b"h" * 32, b"s" * 256)
    left, right = socket.socketpair()

    def sender():
        with left:
            left.sendall(packet)

    thread = threading.Thread(target=sender)
    thread.start()

    with right:
        received = recv_secure_packet(right)

    thread.join(timeout=2)
    assert received == packet