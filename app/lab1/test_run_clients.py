import builtins
from app.lab1.test_client import context, runner
import app.lib.submission as submission
import app.lab1.test_client as test_client
from app.lib.fake_socket import FakeSocket, fake_socket_factory
from app.lib.fake_fd import FakeFd, fake_open_fd_factory, setup_fake_fd_module
import sys
import os
import pytest
import struct
import shlex
import subprocess
import socket
import builtins
import logging
import io
from enum import Enum
from typing import Tuple, Callable


sys.path.insert(0, os.getcwd())
cmd = shlex.split("sudo service tftpd-hpa restart")
subprocess.run(cmd, check=True)


config = test_client.config.CONFIG
code_directory = config['submission_dir_full_path']

# Assert that our paths and config are correct.
assert os.path.isdir(code_directory), f"{code_directory} doesn't exist."
assert len(os.listdir(code_directory)) != 0

submissions = submission.submissions_from_directory(code_directory)
submissions_iter = sorted(list(submissions), key=lambda s: s.module_path)
# test_module_path = "/workspaces/2020-lab1/app/lab1/submissions/2020/1111_2222_lab1.py"
# submissions_iter = [submission.Submission.from_module_path(test_module_path)]

setup_fake_fd_module(code_directory)


def get_test_id(submission_val):
    return str(submission_val)


def get_file_not_found_error(file_name):
    return f"File not found. [{file_name}]"


@pytest.mark.timeout(3)
@pytest.mark.parametrize('submission', submissions_iter, ids=get_test_id)
def test_download_file(caplog, monkeypatch, submission):
    with context.ClientContext.from_submission(submission) as ctx:
        assert os.path.isfile(
            ctx.download_template), "Downloadable file doesn't exist."
        assert os.path.isfile(
            ctx.module_path), f"Couldn't find module {ctx.module_path}"

        download_scenario = runner.ClientScenario.download_file(
            ctx.module_path,
            ctx.download_template
        )
        try:
            run = download_scenario.run()
        except SystemExit:
            logging.warning("Submission called: sys.exit()")

        ctx.check_downloaded_file()


@pytest.mark.timeout(3)
@pytest.mark.parametrize('submission', submissions_iter, ids=get_test_id)
def test_upload_file(submission):
    with context.ClientContext.from_submission(submission) as ctx:
        ctx = context.ClientContext.from_submission(submission)
        upload_scenario = runner.ClientScenario.upload_file(
            ctx.module_path,
            ctx.upload_template
        )

        try:
            run = upload_scenario.run()
        except SystemExit:
            logging.warning("Submission called: sys.exit()")

        ctx.check_uploaded_file()


class TftpOpCodes(Enum):
    RRQ = b"\x00\x01"
    WRQ = b"\x00\x02"
    DATA = b"\x00\x03"
    ACK = b"\x00\x04"
    ERROR = b"\x00\x05"


class Packet(object):
    STRIDE_SIZE = 512

    def __init__(self, opcode: TftpOpCodes):
        self.opcode = opcode

    def __repr__(self):
        if self.opcode == TftpOpCodes.RRQ or self.opcode == TftpOpCodes.WRQ:
            return f"{self.opcode.name} FNAME: {self.fname} MODE: {self.mode}"
        elif self.opcode == TftpOpCodes.DATA:
            return f"DATA #{self.blk} LEN: [{len(self.data)}]"
        elif self.opcode == TftpOpCodes.ACK:
            return f"ACK #{self.blk}"
        elif self.opcode == TftpOpCodes.ERROR:
            return f"ERR ERRCODE: {self.err_code} MSG: {self.err_msg}"

    def __str__(self):
        return self.__repr__()

    @staticmethod
    def parse_packet_bytes(packet_bytes):
        opcode = TftpOpCodes(packet_bytes[:2])

        if opcode == TftpOpCodes.RRQ or opcode == TftpOpCodes.WRQ:
            return Packet.parse_rq_bytes(packet_bytes)
        elif opcode == TftpOpCodes.DATA:
            return Packet.parse_data_bytes(packet_bytes)
        elif opcode == TftpOpCodes.ACK:
            return Packet.parse_ack_bytes(packet_bytes)
        elif opcode == TftpOpCodes.ERROR:
            return Packet.parse_err_bytes(packet_bytes)

    @staticmethod
    def parse_rq_bytes(rq_bytes: bytes):
        p = Packet(TftpOpCodes(rq_bytes[:2]))

        rq_bytes = rq_bytes[2:]
        fname, mode = rq_bytes.split(b"\x00", 1)
        p.fname = str(fname).strip()
        p.mode = str(mode[:-1])

        return p

    @staticmethod
    def parse_data_bytes(data_bytes: bytes):
        p = Packet(TftpOpCodes(data_bytes[:2]))

        p.blk = struct.unpack("!H", data_bytes[2:4])[0]
        p.data = data_bytes[4:]
        p.last = len(p.data) < Packet.STRIDE_SIZE

        if len(p.data) > Packet.STRIDE_SIZE:
            raise ValueError("Invalid data size.")

        return p

    @staticmethod
    def parse_ack_bytes(ack_bytes: bytes):
        p = Packet(TftpOpCodes(ack_bytes[:2]))
        p.blk = struct.unpack("!H", ack_bytes[2:])[0]

        return p

    @staticmethod
    def parse_err_bytes(err_bytes: bytes):
        p = Packet(TftpOpCodes(err_bytes[:2]))

        p.err_code = err_bytes[2:4]
        p.err_msg = err_bytes[4:-1]

        return p

    @staticmethod
    def serialize_packet(packet) -> bytes:
        if packet.opcode == TftpOpCodes.RRQ or packet.opcode == TftpOpCodes.WRQ:
            return Packet.serialize_rq_packet(packet)
        elif packet.opcode == TftpOpCodes.DATA:
            return Packet.serialize_data_packet(packet)
        elif packet.opcode == TftpOpCodes.ACK:
            return Packet.serialize_ack_packet(packet)
        elif packet.opcode == TftpOpCodes.ERROR:
            return Packet.serialize_err_packet(packet)

    @staticmethod
    def serialize_rq_packet(packet) -> bytes:
        buffer = bytearray()

        buffer.append(struct.pack("!H", packet.opcode))
        buffer.append(bytes(packet.fname, "UTF-8"))
        buffer.append(0)
        buffer.append(bytes("octet", "UTF-8"))
        buffer.append(0)

        return bytes(buffer)

    @staticmethod
    def serialize_data_packet(packet) -> bytes:
        buffer = bytearray()
        buffer.append(struct.pack("!HH", packet.opcode, packet.blk))
        buffer.append(packet.data)

        return bytes(buffer)

    @staticmethod
    def serialize_ack_packet(packet) -> bytes:
        buffer = bytearray()
        buffer.append(struct.pack("!HH", packet.opcode, packet.blk))

        return bytes(buffer)

    @staticmethod
    def serialize_err_packet(packet) -> bytes:
        buffer = bytearray()
        buffer.append(struct.pack("!HH", packet.opcode, packet.err_code))
        buffer.append(bytes(packet.err_msg, "UTF-8"))
        buffer.append(0)

        return bytes(buffer)


@pytest.mark.timeout(3)
@pytest.mark.parametrize('submission', submissions_iter, ids=get_test_id)
def test_exp_sending_rrq(caplog, monkeypatch, submission):
    caplog.set_level(logging.DEBUG)
    socket_builder, test_sock = fake_socket_factory(transparent=True)

    def on_sendto(data, address):
        plog = str(Packet.parse_packet_bytes(data))
        logging.debug(f"Sending: {plog} to {address}")

    def on_recvfrom(recv_data):
        data, address = recv_data
        logging.debug(f"Reciving from {address}")
        pass

    test_sock.on_sendto = on_sendto
    test_sock.on_recvfrom = on_recvfrom

    # GO!
    with monkeypatch.context() as m:

        m.setattr(socket, "socket", socket_builder)
        m.setattr(builtins, "open", fake_open_fd_factory)

        # Inject our monkeypatched socket module
        modules = {'socket': socket}
        with context.ClientContext.from_submission(submission) as ctx:
            download_scenario = runner.ClientScenario.download_file(
                ctx.module_path,
                ctx.download_template
            )

            try:
                run = download_scenario.run()
            except SystemExit:
                print("Submission called: sys.exit()")

            assert test_sock.sendto_count > 1
