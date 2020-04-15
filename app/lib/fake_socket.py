import logging
import socket
from typing import Tuple, Callable
unpatched_socket_constructor = socket.socket


class FakeSocket(object):
    """
    Defines a custom socket class that'll be used for testing.
    """

    def __init__(self, address_family, socket_type, transparent=False):
        self.sendto_count = 0
        self.recv_buffer = []
        self.send_buffer = []
        self.on_sendto = None
        self.on_recvfrom = None
        self.transparent = transparent
        self.address_family = address_family
        self.socket_type = socket_type
        self.sys_sock_constructor = unpatched_socket_constructor
        if self.transparent:
            self.sock = self.sys_sock_constructor(address_family, socket_type)

    def sendto(self, data, address):
        self.sendto_count += 1
        self.send_buffer.append((data, address))

        if self.on_sendto is not None:
            self.on_sendto(data, address)

        if self.transparent:
            self.sock.sendto(data, address)

    def recvfrom(self, buffsize):
        if self.transparent:
            recv_packet = self.sock.recvfrom(buffsize)
        else:
            recv_packet = self.recv_buffer.pop(0)
            data, address = recv_packet

            if len(data) < buffsize:
                raise SystemError(
                    "Buffer size is smaller than data, UDP packet will be discarded")

        if self.on_recvfrom is not None:
            self.on_recvfrom(recv_packet)

        return recv_packet

    def settimeout(self, val):
        logging.debug(f"SET TIMEOUT: {val}")

    def close(self):
        logging.debug("CLOSE")

    def to_transparent(self):
        """
        Become a forwarding socket and
        do transfer data to remote
        hosts.
        """
        self.transparent = True
        self.sock = self.sys_sock_constructor(
            self.address_family, self.socket_type)

    def to_opaque(self):
        """
        Stop transfering data to
        remote hosts.
        """
        self.transparent = False
        del self.sock


def fake_socket_factory(transparent=False) -> Tuple[Callable[[int, int], FakeSocket], FakeSocket]:
    """
    Provides a ready socket with a builder.

    The main goal is to be able to get a reference
    to the socket used during the test, to be able
    to extract information about its usage.
    """

    # Provide the unpatched constructor to the
    # object incase it needs to be transparent.
    # otherwise the patched constructor will be
    # used and which will cause infinite recursion.
    test_sock = FakeSocket(-1, -1)

    def f(af, sock):
        logging.debug(f"CONSTRUCT {af} {sock}")
        test_sock.address_family = af
        test_sock.socket_type = sock
        # This is called here because the initalization
        # of the socket outside this function will make
        # -1, -1 the AF_ and SOCK_ values which are
        # invalid.
        if transparent:
            test_sock.to_transparent()
        return test_sock

    return f, test_sock

