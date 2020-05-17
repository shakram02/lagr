import logging
import socket
from typing import Tuple, Callable
unpatched_socket_constructor = socket.socket

SOCK_TIMEOUT = 3


class FakeSocket(object):
    """
    Defines a custom socket class that'll be used for testing.
    """
    # pylint: disable=not-callable

    def __init__(self, address_family, socket_type, transparent=False):
        self.ip_addr = ""
        self.port = 0
        self.sendto_count = 0
        self.recvfrom_count = 0
        self.recv_buffer = []
        self.on_sendto = None
        self.on_recvfrom = None
        self.on_close = None
        self.on_recv = None
        self.transparent = transparent
        self.address_family = address_family
        self.socket_type = socket_type
        self.sys_sock_constructor = unpatched_socket_constructor
        if self.transparent:
            self.to_transparent()

    def sendto(self, data, address):
        self.sendto_count += 1

        if self.on_sendto is not None:
            injected_packet = self.on_sendto(self, data, address)
            # If there's a custom packet to be sent.
            if injected_packet is not None and self.transparent:
                return self.sock.sendto(*injected_packet)

        if self.transparent:
            return self.sock.sendto(data, address)

    def recvfrom(self, buffsize):
        self.recvfrom_count += 1
        if self.transparent:
            recv_packet = self.sock.recvfrom(buffsize)
        else:
            recv_packet = (None, None)

        if self.on_recvfrom is not None:
            injected = self.on_recvfrom(self, recv_packet)
            if injected is not None:
                return injected

        data, address = recv_packet
        if len(data) > buffsize:
            raise SystemError(
                "Buffer size is smaller than data, UDP packet will be discarded")

        return recv_packet

    def recv(self, buffsize):
        """
        Returns data only.
        """
        if self.transparent:
            recv_packet = self.sock.recv(buffsize)
        else:
            recv_packet = None

        if self.on_recv is not None:
            injected = self.on_recv(self, recv_packet)
            if injected is not None:
                return injected

        return recv_packet

    def bind(self, addr):
        ip, port = addr
        self.ip_addr = ip
        self.port = port

        logging.debug(f"BIND: {addr}")

        if self.transparent:
            # Break dependency between tests.
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(addr)

    def settimeout(self, val):
        logging.debug(f"SET TIMEOUT: {val}")

    def close(self):
        if self.transparent:
            self.sock.close()
        if self.on_close is not None:
            self.on_close(self)
        logging.debug("CLOSE")

    def setblocking(self, val):
        # TODO: what should I do?
        # report bonus.
        pass

    def fileno(self):
        # For non-blocking socket.
        if self.transparent:
            return self.sock.fileno()
        else:
            raise RuntimeError(
                "[GRADER ERROR] Can't have fileno of non-transparent socket")

    def getsockname(self):
        return f"{self.ip_addr}:{self.port}"

    def to_transparent(self):
        """
        Become a forwarding socket and
        do transfer data to remote
        hosts.
        """
        self.transparent = True
        self.sock = self.sys_sock_constructor(
            self.address_family, self.socket_type)
        self.sock.settimeout(SOCK_TIMEOUT)

    def to_opaque(self):
        """
        Stop transfering data to
        remote hosts.
        """
        self.transparent = False
        del self.sock

    def __del__(self):
        if self.transparent:
            try:
                self.sock.close()
            except Exception:
                pass


def fake_socket_factory(on_sendto=None, on_recvfrom=None, transparent=False, on_close=None) -> Callable[[int, int], FakeSocket]:
    """
    Provides a ready socket with a builder.

    The main goal is to be able to get a reference
    to the socket used during the test, to be able
    to extract information about its usage.
    """
    def f(family=socket.AF_INET, type=socket.SOCK_STREAM):
        nonlocal transparent
        nonlocal on_recvfrom
        nonlocal on_sendto
        # Provide the unpatched constructor to the
        # object incase it needs to be transparent.
        # otherwise the patched constructor will be
        # used and which will cause infinite recursion.
        test_sock = FakeSocket(family, type, transparent)
        test_sock.on_recvfrom = on_recvfrom
        test_sock.on_sendto = on_sendto
        test_sock.on_close = on_close

        logging.debug(f"CONSTRUCT {family} {type}")
        return test_sock

    return f
