"""
In packet testing we accept that code uses any TID, since asserting
making new socket for each client is covered in its test,
it shouldn't make other tests fail since this is so cruel.

Please note that server runs in a different process which
makes code sharing hard and logging impossible without using
print statements.

Testing for errors only occurs for invalid RRQs, since
overwriting a file using an WRQ doesn't look really invalid.
"""
import sys
import os
import shlex
import subprocess
import socket
import logging
import time
import pytest
import threading

from app.lab1 import context, runner, config
from app.lab1.config import TEST_TIMEOUT
import app.lib.submission as submission
from app.lib.fake_socket import FakeSocket, fake_socket_factory
from app.lib.fake_fd import FakeFd, fake_open_fd_factory, setup_fake_fd_module
from app.lib.helpers import TerminateFail, TerminatePass, wait_for_file, SLEEP_DURATION, TEST_PASS_ATTR, check_test_pass, mark_test_pass, mark_test_fail_on_dead_process
from app.lab1.tftp_lib import Packet, TftpOpCodes
from typing import Tuple, Callable


config = config.CONFIG
code_directory = config["server_submission_dir_full_path"]
setup_fake_fd_module(code_directory)
os.chdir(config['scratch_disk'])


FAKE_CLIENT_ADDR = ("127.0.0.1", 8777)

cmd = shlex.split("sudo service tftpd-hpa restart")
subprocess.run(cmd, check=True)

# Assert that our paths and config are correct.
assert os.path.isdir(code_directory), f"{code_directory} doesn't exist."
assert len(os.listdir(code_directory)) != 0

submissions_iter = submission.submissions_from_directory(code_directory)
# test_module_path = "/workspaces/2020-lab1/app/lab1/submissions/2020/server/4847_lab1 - Meeral Maged.py"
# submissions_iter = [submission.Submission.from_module_path(test_module_path)]


def process_exception(server_process):
    if server_process.has_exception:
        completion_exception = server_process.exception
        raise TerminateFail(completion_exception.tb)


def server_teardown(server_process):
    # server_process.terminate()
    if server_process.has_exception:
        # Raised from on_sendto/on_recvfrom.
        # If sending proceeds, the server should
        # send an error packet and the assertion will fail,
        # but it won't have the custom property.
        completion_exception = server_process.exception
        if not hasattr(completion_exception, TEST_PASS_ATTR):
            server_process.log_existing_process_output()
            process_exception(server_process)
    else:
        server_process.log_existing_process_output()
        # We can leave the test to timeout too, but this is more explicit.
        raise TerminateFail("Expected a test termination exception")


@pytest.mark.parametrize('submission', submissions_iter, ids=submission.get_test_id)
def test_server_download_file(caplog, monkeypatch, submission):
    caplog.set_level(logging.DEBUG)
    socket_builder = fake_socket_factory(transparent=True)

    with context.ServerContext.from_submission(submission) as ctx:
        download_scenario = runner.ServerScenario.download_file_scenario(
            ctx.module_path, ctx.done_file)
        with monkeypatch.context() as m:
            server_process = download_scenario.establish_server_run_env()
            client_process = download_scenario.establish_client_run_env(
                ctx.template_file)

            m.setattr(socket, "socket", socket_builder)
            server_process.start()

            time.sleep(SLEEP_DURATION/10)
            client_process.start()
            client_process.join()

            server_process.join()
            server_process.log_existing_process_output()
            process_exception(server_process)
            ctx.check_file()


@pytest.mark.parametrize('submission', submissions_iter, ids=submission.get_test_id)
def test_server_upload_file(caplog, monkeypatch, submission):
    caplog.set_level(logging.DEBUG)
    socket_builder = fake_socket_factory(transparent=True)

    with context.ServerContext.from_submission(submission) as ctx:
        upload_scenario = runner.ServerScenario.upload_file_scenario(
            ctx.module_path, ctx.done_file)
        with monkeypatch.context() as m:
            server_process = upload_scenario.establish_server_run_env()
            client_process = upload_scenario.establish_client_run_env(
                ctx.template_file)
            m.setattr(socket, "socket", socket_builder)
            server_process.start()

            time.sleep(SLEEP_DURATION/10)
            client_process.start()
            client_process.join()

            server_process.join()
            server_process.log_existing_process_output()
            process_exception(server_process)
            ctx.check_file()


@pytest.mark.parametrize('submission', submissions_iter, ids=submission.get_test_id)
def test_server_receive_rrq(caplog, monkeypatch, submission):
    """
        Flow
        client: RRQ
        server: ACK #0
    """
    with context.ServerContext.from_submission(submission) as ctx:
        def on_recvfrom(test_sock: FakeSocket, recv_data):
            target_file = ctx.template_file
            wait_for_file(ctx.template_file)

            p = Packet.make_rrq(target_file)
            data = Packet.serialize_packet(p)

            return (data, FAKE_CLIENT_ADDR)

        def on_sendto(test_sock: FakeSocket, data, address):
            assert address == FAKE_CLIENT_ADDR
            p: Packet = Packet.parse_packet_bytes(data)
            assert p.opcode == TftpOpCodes.DATA, str(p)
            mark_test_pass()

        caplog.set_level(logging.DEBUG)
        socket_builder = fake_socket_factory(
            on_recvfrom=on_recvfrom, on_sendto=on_sendto, transparent=False)

        download_scenario = runner.ServerScenario.download_file_scenario(
            ctx.module_path, ctx.done_file)

        with monkeypatch.context() as m:
            server_process = download_scenario.establish_server_run_env()
            m.setattr(socket, "socket", socket_builder)

            server_process.start()
            # Wait for the process to raise, or test to timeout
            server_process.join()
            server_teardown(server_process)


@pytest.mark.parametrize('submission', submissions_iter, ids=submission.get_test_id)
def test_server_receive_wrq(caplog, monkeypatch, submission):
    """
        Flow
        client: WRQ
        server: ACK #0
    """
    with context.ServerContext.from_submission(submission) as ctx:
        def on_recvfrom(test_sock: FakeSocket, recv_data):
            target_file = ctx.done_file  # Non-existent file
            p = Packet.make_wrq(target_file)
            data = Packet.serialize_packet(p)

            return (data, FAKE_CLIENT_ADDR)

        def on_sendto(test_sock: FakeSocket, data, address):
            assert address == FAKE_CLIENT_ADDR
            p: Packet = Packet.parse_packet_bytes(data)
            assert p.opcode == TftpOpCodes.ACK, str(p)
            assert p.blk == 0, str(p)
            mark_test_pass()

        caplog.set_level(logging.DEBUG)
        socket_builder = fake_socket_factory(
            on_recvfrom=on_recvfrom, on_sendto=on_sendto, transparent=False)

        download_scenario = runner.ServerScenario.download_file_scenario(
            ctx.module_path, ctx.done_file)
        with monkeypatch.context() as m:
            server_process = download_scenario.establish_server_run_env()
            m.setattr(socket, "socket", socket_builder)

            server_process.start()
            # Wait for the process to raise, or test to timeout
            server_process.join()
            server_teardown(server_process)


@pytest.mark.parametrize('submission', submissions_iter, ids=submission.get_test_id)
def test_server_sends_data(caplog, monkeypatch, submission):
    """
        Flow
        client: RRQ
        server: DATA #1
    """
    with context.ServerContext.from_submission(submission) as ctx:
        def on_recvfrom(test_sock: FakeSocket, recv_data):
            target_file = ctx.template_file  # Non-existent file
            p = Packet.make_rrq(target_file)
            data = Packet.serialize_packet(p)

            return (data, FAKE_CLIENT_ADDR)

        def on_sendto(test_sock: FakeSocket, data, address):
            assert address == FAKE_CLIENT_ADDR
            p: Packet = Packet.parse_packet_bytes(data)
            assert p.opcode == TftpOpCodes.DATA, str(p)
            assert p.blk == 1, str(p)
            mark_test_pass()

        caplog.set_level(logging.DEBUG)
        socket_builder = fake_socket_factory(
            on_recvfrom=on_recvfrom, on_sendto=on_sendto, transparent=False)

        download_scenario = runner.ServerScenario.download_file_scenario(
            ctx.module_path, ctx.done_file)
        with monkeypatch.context() as m:
            server_process = download_scenario.establish_server_run_env()
            m.setattr(socket, "socket", socket_builder)

            server_process.start()
            # Wait for the process to raise, or test to timeout
            server_process.join()
            server_teardown(server_process)


@pytest.mark.parametrize('submission', submissions_iter, ids=submission.get_test_id)
@pytest.mark.timeout(TEST_TIMEOUT)
def test_server_receive_data_and_then_ack_it(caplog, monkeypatch, submission):
    """
        Flow
        client: WRQ
        server: ACK #0
        client: DATA #1
        server: ACK #1
    """
    with context.ServerContext.from_submission(submission) as ctx:
        fake_data = str.encode("test_data_wo", "UTF-8")
        caplog.set_level(logging.DEBUG)
        download_scenario = runner.ServerScenario.download_file_scenario(
            ctx.module_path, ctx.done_file)
        sendto_count = 0
        recvfrom_count = 0

        def on_recvfrom(test_sock: FakeSocket, recv_data):
            nonlocal fake_data
            nonlocal recvfrom_count
            print("SOCKETPORT:", test_sock.port)
            # Send an WRQ
            if recvfrom_count == 0:
                recvfrom_count += 1
                target_file = ctx.done_file
                p = Packet.make_wrq(target_file)
                data = Packet.serialize_packet(p)
                return (data, FAKE_CLIENT_ADDR)

            if recvfrom_count == 1:
                recvfrom_count += 1
                p = Packet.make_data(1, fake_data)
                data = Packet.serialize_packet(p)
                return (data, FAKE_CLIENT_ADDR)
            else:
                # The test should've failed/returned.
                raise TerminateFail("Unreachable.")

        def on_sendto(test_sock: FakeSocket, data, address):
            nonlocal sendto_count
            p: Packet = Packet.parse_packet_bytes(data)
            # WRQ's reply is ACK#0
            if sendto_count == 0:
                assert address == FAKE_CLIENT_ADDR
                assert p.opcode == TftpOpCodes.ACK, str(p)
                assert p.blk == 0, str(p)
                sendto_count += 1
                return
            elif sendto_count == 1:
                # ACK first data block
                assert address == FAKE_CLIENT_ADDR
                assert p.opcode == TftpOpCodes.ACK, str(p)
                assert p.blk == 1, str(p)
                mark_test_pass()

            # Wrong paths. The test should either fail or return.
            raise TerminateFail("Unreachable.")

        socket_builder = fake_socket_factory(
            on_recvfrom=on_recvfrom, on_sendto=on_sendto, transparent=False)
        with monkeypatch.context() as m:
            server_process = download_scenario.establish_server_run_env()
            m.setattr(socket, "socket", socket_builder)

            server_process.start()
            # Wait for the process to raise, or test to timeout
            server_process.join()
            server_teardown(server_process)


@pytest.mark.parametrize('submission', submissions_iter, ids=submission.get_test_id)
@pytest.mark.timeout(TEST_TIMEOUT)
def test_server_receive_ack(caplog, monkeypatch, submission):
    """
        Flow
        client: RRQ
        server: DATA #1
        client: ACK #1
        server: DATA #2
    """
    with context.ServerContext.from_submission(submission) as ctx:
        recvfrom_count = 0
        sendto_count = 0

        def on_recvfrom(test_sock: FakeSocket, recv_data):
            nonlocal recvfrom_count
            if recvfrom_count == 0:
                target_file = ctx.template_file
                wait_for_file(ctx.template_file)

                p = Packet.make_rrq(target_file)
                data = Packet.serialize_packet(p)
            elif recvfrom_count == 1:
                p = Packet.make_ack(1)
                data = Packet.serialize_packet(p)
            else:
                raise TerminateFail("Unexpected number of recvfrom() calls")

            recvfrom_count += 1
            return (data, FAKE_CLIENT_ADDR)

        def on_sendto(test_sock: FakeSocket, data, address):
            nonlocal sendto_count
            if sendto_count == 1:
                assert address == FAKE_CLIENT_ADDR
                p: Packet = Packet.parse_packet_bytes(data)
                assert p.opcode == TftpOpCodes.DATA, str(p)
                assert p.blk == 2, str(p)
                mark_test_pass()
            elif sendto_count > 1:
                raise TerminateFail("Unexpected number of sendto() calls")

            sendto_count += 1

        caplog.set_level(logging.DEBUG)
        socket_builder = fake_socket_factory(
            on_recvfrom=on_recvfrom, on_sendto=on_sendto, transparent=False)
        download_scenario = runner.ServerScenario.download_file_scenario(
            ctx.module_path, ctx.done_file)

        with monkeypatch.context() as m:
            server_process = download_scenario.establish_server_run_env()
            m.setattr(socket, "socket", socket_builder)

            server_process.start()
            # Wait for the process to raise, or test to timeout
            server_process.join()
            server_teardown(server_process)


@pytest.mark.parametrize('submission', submissions_iter, ids=submission.get_test_id)
@pytest.mark.timeout(TEST_TIMEOUT)
def test_server_receive_err(caplog, monkeypatch, submission):
    """
        Flow
        client: WRQ
        server: ACK #0
        client: ERR
        server: close
    """
    with context.ServerContext.from_submission(submission) as ctx:
        recvfrom_count = 0
        sendto_count = 0

        # The server should close the client's
        # connection once an error packet
        # is received.
        def on_close(test_sock: FakeSocket):
            mark_test_pass()

        def on_recvfrom(test_sock: FakeSocket, recv_data):
            nonlocal recvfrom_count
            if recvfrom_count == 0:
                target_file = ctx.done_file  # Non-existent file
                p = Packet.make_wrq(target_file)
                data = Packet.serialize_packet(p)
            elif recvfrom_count == 1:
                p = Packet.make_err(1, "random error packet.")
                data = Packet.serialize_packet(p)
            else:
                # If the server called close, the test would've passed.
                # but the server decided to ignore the error sent by
                # the client and continue receiving.
                raise TerminateFail("Expected to close client socket.")

            recvfrom_count += 1
            return (data, FAKE_CLIENT_ADDR)

        def on_sendto(test_sock: FakeSocket, data, address):
            nonlocal sendto_count
            # sendto_count == 0 sends ACK #0
            if sendto_count == 1:
                raise TerminateFail("Expected to close client socket.")

            sendto_count += 1

        caplog.set_level(logging.DEBUG)
        socket_builder = fake_socket_factory(
            on_recvfrom=on_recvfrom, on_sendto=on_sendto, on_close=on_close, transparent=False)

        download_scenario = runner.ServerScenario.download_file_scenario(
            ctx.module_path, ctx.done_file)
        with monkeypatch.context() as m:
            server_process = download_scenario.establish_server_run_env()
            m.setattr(socket, "socket", socket_builder)

            server_process.start()
            # Wait for the process to raise, or test to timeout
            server_process.join()
            server_teardown(server_process)


@pytest.mark.parametrize('submission', submissions_iter, ids=submission.get_test_id)
@pytest.mark.timeout(TEST_TIMEOUT)
def test_server_send_err_on_bad_packet(caplog, monkeypatch, submission):
    """
        Flow
        client: BAD
        server: ERR
    """
    with context.ServerContext.from_submission(submission) as ctx:
        def on_recvfrom(test_sock: FakeSocket, _):
            return (b"\x00\xff\x00\x01", FAKE_CLIENT_ADDR)

        def on_sendto(test_sock: FakeSocket, data, address):
            assert address == FAKE_CLIENT_ADDR
            p: Packet = Packet.parse_packet_bytes(data)
            assert p.opcode == TftpOpCodes.ERROR, str(p)
            mark_test_pass()

        caplog.set_level(logging.DEBUG)
        socket_builder = fake_socket_factory(
            on_recvfrom=on_recvfrom, on_sendto=on_sendto, transparent=False)
        download_scenario = runner.ServerScenario.download_file_scenario(
            ctx.module_path, ctx.done_file)

        with monkeypatch.context() as m:
            server_process = download_scenario.establish_server_run_env()
            m.setattr(socket, "socket", socket_builder)

            server_process.start()
            # Wait for the process to raise, or test to timeout
            server_process.join()
            server_teardown(server_process)


@pytest.mark.parametrize('submission', submissions_iter, ids=submission.get_test_id)
@pytest.mark.timeout(TEST_TIMEOUT)
def test_server_sends_err_after_invalid_rrq_non_existing_file(caplog, monkeypatch, submission):
    """
        Flow
        client: RRQ (non-existing file)
        server: Error (not found)
    """
    with context.ServerContext.from_submission(submission) as ctx:
        def on_recvfrom(test_sock: FakeSocket, recv_data):
            target_file = ctx.done_file  # Non-existent file
            p = Packet.make_rrq(target_file)
            data = Packet.serialize_packet(p)

            return (data, FAKE_CLIENT_ADDR)

        def on_sendto(test_sock: FakeSocket, data, address):
            assert address == FAKE_CLIENT_ADDR
            p: Packet = Packet.parse_packet_bytes(data)
            assert p.opcode == TftpOpCodes.ERROR, str(p)
            mark_test_pass()

        caplog.set_level(logging.DEBUG)
        socket_builder = fake_socket_factory(
            on_recvfrom=on_recvfrom, on_sendto=on_sendto, transparent=False)

        download_scenario = runner.ServerScenario.download_file_scenario(
            ctx.module_path, ctx.done_file)
        with monkeypatch.context() as m:
            server_process = download_scenario.establish_server_run_env()
            m.setattr(socket, "socket", socket_builder)

            server_process.start()
            # Wait for the process to raise, or test to timeout
            server_process.join()
            server_teardown(server_process)


@pytest.mark.parametrize('submission', submissions_iter, ids=submission.get_test_id)
@pytest.mark.timeout(TEST_TIMEOUT)
def test_server_uses_different_tid(caplog, monkeypatch, submission):
    """
        Checks that a server knows about making new TID (socket)
        for each connecting client.

        Flow
        client: RRQ [to SERVER_PORT]
        server: DATA #1 [from OTHER_PORT]
    """
    with context.ServerContext.from_submission(submission) as ctx:
        recvfrom_count = 0
        sendto_count = 0

        def on_recvfrom(test_sock: FakeSocket, recv_data):
            nonlocal recvfrom_count
            if recvfrom_count == 0:
                target_file = ctx.template_file
                wait_for_file(ctx.template_file)

                p = Packet.make_rrq(target_file)
                data = Packet.serialize_packet(p)
            else:
                raise TerminateFail()

            recvfrom_count += 1
            return (data, FAKE_CLIENT_ADDR)

        def on_sendto(test_sock: FakeSocket, data, address):
            nonlocal sendto_count
            if sendto_count == 0:
                assert test_sock.port != runner.ServerScenario.SUBMISSION_MODULE_PORT, "Didn't use new socket for client."
                mark_test_pass()

            sendto_count += 1

        caplog.set_level(logging.DEBUG)
        socket_builder = fake_socket_factory(
            on_recvfrom=on_recvfrom, on_sendto=on_sendto, transparent=False)
        download_scenario = runner.ServerScenario.download_file_scenario(
            ctx.module_path, ctx.done_file)

        with monkeypatch.context() as m:
            server_process = download_scenario.establish_server_run_env()
            m.setattr(socket, "socket", socket_builder)

            server_process.start()
            # Wait for the process to raise, or test to timeout
            server_process.join()
            server_teardown(server_process)
