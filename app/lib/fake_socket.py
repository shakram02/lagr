import logging
import socket
import struct
from app.lib.helpers import is_called_from_submission_code
from app.lib.interceptable_object import InterceptableObject
from typing import Tuple, Callable
from socket import AF_INET, SOCK_STREAM
unpatched_socket_constructor = socket.socket

SOCK_TIMEOUT = 3

# We didn't inherit because we want everything to be strictly defined.
# some submissions call functions that we don't take into consideration
# and their code should crash.


class FakeSocket(InterceptableObject):
    """
    Defines a custom socket class that'll be used for testing.
    """
    # pylint: disable=not-callable
    FAKE_SOCKET_PORT = 24313

    def __init__(self, address_family, socket_type, transparent=False):
        self.ip_addr = None
        self.port = None
        self.sendto_count = 0
        self.recvfrom_count = 0
        self.send_count = 0
        self.accept_count = 0
        self.recv_buffer = []
        self.event_handlers = {}

        self.transparent = transparent
        self.address_family = address_family
        self.socket_type = socket_type
        self.sys_sock_constructor = unpatched_socket_constructor
        if self.transparent:
            self.to_transparent()

    def send(self, data):
        logging.debug(f"SEND")
        self.send_count += 1

        if self.on_send:
            injected_packet = self.on_send(self, data)
            if injected_packet and self.transparent:
                return self.sock.send(injected_packet)

        if self.transparent:
            return self.sock.send(data)

    def sendall(self, data):
        logging.debug(f"SENDALL")
        self.send_count += 1
        if self.on_send:
            injected_packet = self.on_send(self, data)
            if injected_packet and self.transparent:
                return self.sock.sendall(injected_packet)

        if self.transparent:
            return self.sock.sendall(data)

    def sendto(self, data, address):
        logging.debug(f"SENDTO")
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
        logging.debug(f"RECVFROM")
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
        logging.debug(f"RECV")
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
        logging.debug(f"BIND: {addr}")
        if self.on_bind is not None:
            proxy_to_system_sock = self.on_bind(self, addr)
            if not proxy_to_system_sock:
                return

        ip, port = addr
        if self.ip_addr is None:
            self.ip_addr = ip
        if self.port is None:
            self.port = port

        if self.transparent:
            # Break dependency between tests.
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # https://www.programcreek.com/python/example/67443/socket.SO_LINGER
            # Set SO_LINGER to 1,0 which, by convention, causes a
            # connection reset to be sent when close is called,
            # instead of the standard FIN shutdown sequenc

            # http://man7.org/linux/man-pages/man7/socket.7.html
            # When enabled, a close(2) or shutdown(2) will not return until
            #   all queued messages for the socket have been successfully sent
            #   or the linger timeout has been reached.  Otherwise, the call
            #   returns immediately and the closing is done in the background.
            #   When the socket is closed as part of exit(2), it always
            #   lingers in the background.
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                 struct.pack("ii", 1, 0))
            # try:
            self.sock.bind(addr)
            # except OSError as e:
            #     bip, bp = addr
            #     if e.errno == 22 and bip == self.ip_addr:
            #         logging.warning(
            #             f"Binding to invalid [test] address:{addr}")
            #     else:
            #         raise e

    def connect(self, addr):
        logging.debug(f"CONNECT: {addr}")
        if self.on_connect is not None:
            proxy_to_system_sock = self.on_connect(self, addr)
            if not proxy_to_system_sock:
                return

        if self.transparent:
            self.sock.connect(addr)

    def accept(self):
        self.accept_count += 1
        logging.debug(f"ACCEPT")
        if self.on_accept:
            proxy_to_system_sock = self.on_accept(self)

            if proxy_to_system_sock is not None:
                return proxy_to_system_sock

        if self.transparent:
            return self.sock.accept()

    def listen(self, backlog=0):
        logging.debug(f"LISTEN")
        if self.on_listen:
            proxy_to_system_sock = self.on_listen(self, backlog)
            if not proxy_to_system_sock:
                return

        if self.port is None:
            self.port = FakeSocket.FAKE_SOCKET_PORT
        if self.ip_addr is None:
            self.ip_addr = "0.0.0.0"
        if self.transparent:
            self.sock.listen(backlog)

    def close(self):
        logging.debug("CLOSE")
        if self.transparent:
            self.sock.close()
        if self.on_close is not None:
            self.on_close(self)

    def settimeout(self, val):
        logging.debug(f"SET TIMEOUT: {val}")

    def setblocking(self, val):
        # TODO: what should I do?
        # report bonus.?
        pass

    def fileno(self):
        # For non-blocking socket.
        if self.transparent:
            return self.sock.fileno()
        else:
            raise RuntimeError(
                "[GRADER ERROR] Can't have fileno of non-transparent socket")

    def getsockname(self):
        logging.debug("GETSOCKNAME")
        if self.on_getsockname:
            sn = self.on_getsockname(self)
            if sn:
                return sn

        if self.transparent:
            return self.sock.getsockname()

        return f"{self.ip_addr}", self.port

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
            except Exception as err:
                raise err

    def setsockopt(self, *args, **kwargs):
        if self.transparent:
            self.sock.setsockopt(*args, **kwargs)
        else:
            pass

    def __enter__(self):
        return self

    def __exit__(self, excpetion_type, excetion_value, traceback):
        if self.transparent:
            self.sock.close()


def fake_socket_factory(
    submission_directory,
    transparent=False,
    **kwargs
) -> Callable[[int, int], FakeSocket]:
    """
    Provides a ready socket with a builder.

    The main goal is to be able to get a reference
    to the socket used during the test, to be able
    to extract information about its usage.
    """
    import traceback

    def f(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, fileno=None):
        nonlocal transparent
        nonlocal submission_directory

        if not is_called_from_submission_code(submission_directory):
            return unpatched_socket_constructor(family, type, proto, fileno)

        # Provide the unpatched constructor to the
        # object incase it needs to be transparent.
        # otherwise the patched constructor will be
        # used and which will cause infinite recursion.
        test_sock = FakeSocket(family, type, transparent)
        for key, value in kwargs.items():
            test_sock.__setattr__(key, value)

        logging.debug(f"CONSTRUCT {family} {type}")
        return test_sock

    return f
