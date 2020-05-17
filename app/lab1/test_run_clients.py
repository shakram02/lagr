import os
import shlex
import subprocess
import socket
import logging
import pytest
import builtins
import app.lib.submission as submission

from app.lab1 import context, runner, config
from app.lab1.config import TEST_TIMEOUT
from app.lib.fake_socket import FakeSocket, fake_socket_factory
from app.lib.fake_fd import FakeFd, fake_open_fd_factory, setup_fake_fd_module
from app.lib.helpers import TerminateFail, TerminatePass, mark_test_pass
from app.lab1.tftp_lib import Packet, TftpOpCodes
from typing import Tuple, Callable

config = config.CONFIG
os.chdir(config['scratch_disk'])
code_directory = config["client_submission_dir_full_path"]

cmd = shlex.split("sudo service tftpd-hpa restart")
subprocess.run(cmd, check=True)

# Assert that our paths and config are correct.
assert os.path.isdir(code_directory), f"{code_directory} doesn't exist."
assert len(os.listdir(code_directory)) != 0

submissions_iter = submission.submissions_from_directory(code_directory)
# test_module_path = "/workspaces/2020-lab1/app/lab1/submissions/2020/client/4617_4762_lab1 - Fayez Elmassry.py"
# submissions_iter = [submission.Submission.from_module_path(test_module_path)]

setup_fake_fd_module(code_directory)


def get_file_not_found_error(file_name):
    return f"File not found. [{file_name}]"


@pytest.mark.parametrize('submission', submissions_iter, ids=submission.get_test_id)
@pytest.mark.timeout(TEST_TIMEOUT)
class TestTftpClientRx:
    def test_upload_file(self, submission):
        with context.ClientContext.from_submission(submission) as ctx:
            upload_scenario = runner.ClientScenario.upload_file(
                ctx.module_path,
                ctx.upload_template
            )

            try:
                run = upload_scenario.run()
            except SystemExit:
                logging.warning("Submission called: sys.exit()")

            ctx.check_uploaded_file()

    def test_client_should_send_err(self, caplog, monkeypatch, submission):
        """
        Test that the code sends an ACK after the first data
        """
        def on_recvfrom(test_sock, recv_data):
            data, address = recv_data
            return (b"\x00\xff\x00\x01", address)

        def on_sendto(test_sock, data, address):
            p = Packet.parse_packet_bytes(data)
            plog = str(p)
            logging.debug(f"Sending: {plog} to {address}")

            if p.opcode == TftpOpCodes.RRQ:
                fname = f"{submission}_download_file-template.txt"
                injected = Packet.make_rrq(fname)
                logging.debug(f"[>] Sending: {injected} to {address}")
                assert test_sock.sendto_count == 1
                return (Packet.serialize_packet(injected), address)

            # In this test case, the code should send an error.
            # since we sent a malformed packet.
            if test_sock.sendto_count == 2:
                assert p.opcode == TftpOpCodes.ERROR
                mark_test_pass()

            if test_sock.sendto_count > 2:
                raise TerminateFail("Expected an ERROR packet")

        caplog.set_level(logging.DEBUG)
        socket_builder = fake_socket_factory(
            on_sendto=on_sendto, on_recvfrom=on_recvfrom, transparent=True)

        with context.ClientContext.from_submission(submission) as ctx:
            download_scenario = runner.ClientScenario.download_file(
                ctx.module_path,
                ctx.download_template
            )
            with monkeypatch.context() as m:
                m.setattr(socket, "socket", socket_builder)

                try:
                    run = download_scenario.run()
                except SystemExit:
                    pass
                except TerminatePass:
                    pass

    def test_client_can_receive_err(self, caplog, monkeypatch, submission):
        """
        Test that the code sends an ACK after the first data
        """
        def on_recvfrom(test_sock, recv_data):
            data, address = recv_data
            p = Packet.make_err(1, "Operation failed.")
            return (Packet.serialize_err_packet(p), address)

        def on_sendto(test_sock, data, address):
            p = Packet.parse_packet_bytes(data)
            plog = str(p)
            logging.debug(f"Sending: {plog} to {address}")

            if p.opcode == TftpOpCodes.RRQ:
                fname = f"{submission}_download_file-template.txt"
                injected = Packet.make_rrq(fname)
                logging.debug(f"[>] Sending: {injected} to {address}")
                assert test_sock.sendto_count == 1
                return (Packet.serialize_packet(injected), address)
            else:
                raise TerminateFail("Didn't terminate on Error.")

        caplog.set_level(logging.DEBUG)
        socket_builder = fake_socket_factory(
            on_sendto=on_sendto, on_recvfrom=on_recvfrom, transparent=True)

        with context.ClientContext.from_submission(submission) as ctx:
            download_scenario = runner.ClientScenario.download_file(
                ctx.module_path,
                ctx.download_template
            )

            with monkeypatch.context() as m:
                m.setattr(socket, "socket", socket_builder)

                try:
                    run = download_scenario.run()
                except SystemExit:
                    pass


@pytest.mark.parametrize('submission', submissions_iter, ids=submission.get_test_id)
@pytest.mark.timeout(TEST_TIMEOUT)
class TestTftpClientTx:
    @pytest.mark.parent
    def test_download_file(self, caplog, monkeypatch, submission):
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

    @pytest.mark.child
    def test_client_send_rrq(self, caplog, monkeypatch, submission):
        def on_sendto(test_sock, data, address):
            p = Packet.parse_packet_bytes(data)
            plog = str(p)
            logging.debug(f"Sending: {plog} to {address}")

            if p.opcode == TftpOpCodes.RRQ:
                assert test_sock.sendto_count == 1
                test_sock.assert_rrq = True
                raise TerminatePass()
            else:
                raise TerminateFail("Expected an RRQ")

        def on_recvfrom(test_sock, recv_data):
            data, address = recv_data
            packet = Packet.parse_packet_bytes(data)
            logging.debug(
                f"RECV from {address}: [{len(data)}] byte(s) {str(packet)}")

        caplog.set_level(logging.DEBUG)
        socket_builder = fake_socket_factory(
            on_sendto=on_sendto, on_recvfrom=on_recvfrom, transparent=True)

        with context.ClientContext.from_submission(submission) as ctx:
            download_scenario = runner.ClientScenario.download_file(
                ctx.module_path,
                ctx.download_template
            )
            # GO!
            with monkeypatch.context() as m:
                m.setattr(socket, "socket", socket_builder)

                try:
                    run = download_scenario.run()
                except TerminatePass:
                    logging.debug("Passed")

    @pytest.mark.child
    def test_client_send_wrq(self, caplog, monkeypatch, submission):
        def on_sendto(test_sock, data, address):
            p = Packet.parse_packet_bytes(data)
            plog = str(p)
            logging.debug(f"Sending: {plog} to {address}")

            if p.opcode == TftpOpCodes.WRQ:
                assert test_sock.sendto_count == 1
                test_sock.assert_wrq = True
                raise TerminatePass()
            else:
                raise TerminateFail("Expected an WRQ")

        def on_recvfrom(test_sock, recv_data):
            data, address = recv_data
            packet = Packet.parse_packet_bytes(data)
            logging.debug(
                f"RECV from {address}: [{len(data)}] byte(s) {str(packet)}")

        caplog.set_level(logging.DEBUG)
        socket_builder = fake_socket_factory(
            on_sendto=on_sendto, on_recvfrom=on_recvfrom, transparent=True)

        with context.ClientContext.from_submission(submission) as ctx:
            with monkeypatch.context() as m:
                m.setattr(socket, "socket", socket_builder)
                upload_scenario = runner.ClientScenario.upload_file(
                    ctx.module_path,
                    ctx.upload_template
                )

                try:
                    run = upload_scenario.run()
                except TerminatePass:
                    logging.debug("Passed")

    @pytest.mark.child
    def test_client_send_data(self, caplog, monkeypatch, submission):
        def on_sendto(test_sock, data, address):
            p = Packet.parse_packet_bytes(data)
            plog = str(p)
            logging.debug(f"Sending: {plog} to {address}")

            if p.opcode == TftpOpCodes.WRQ:
                fname = f"{submission}_upload_file-template.txt"
                injected = Packet.make_wrq(fname)
                logging.debug(f"[>] Sending: {injected} to {address}")
                assert test_sock.sendto_count == 1
                return (Packet.serialize_packet(injected), address)

            # ACK is the second packet to be sent when receiving data.
            if test_sock.sendto_count == 2:
                assert p.opcode == TftpOpCodes.DATA
                assert p.blk == 1
                test_sock.pass_data = True
                raise TerminatePass()

            if test_sock.sendto_count > 2:
                raise TerminateFail("Expected a DATA packet.")

        def on_recvfrom(test_sock, recv_data):
            data, address = recv_data
            packet = Packet.parse_packet_bytes(data)
            logging.debug(
                f"RECV from {address}: [{len(data)}] byte(s) {str(packet)}")

        caplog.set_level(logging.DEBUG)
        socket_builder = fake_socket_factory(
            on_sendto=on_sendto, on_recvfrom=on_recvfrom, transparent=True)

        with context.ClientContext.from_submission(submission) as ctx:
            with monkeypatch.context() as m:
                m.setattr(socket, "socket", socket_builder)
                upload_scenario = runner.ClientScenario.upload_file(
                    ctx.module_path,
                    ctx.upload_template
                )

                try:
                    run = upload_scenario.run()
                except TerminatePass:
                    logging.debug("Passed")

    def test_client_send_ack(self, caplog, monkeypatch, submission):
        """
        Test that the code sends an ACK after the first data
        """
        def on_recvfrom(test_sock, recv_data):
            data, address = recv_data
            packet = Packet.parse_packet_bytes(data)
            logging.debug(
                f"RECV {address}: [{len(data)}] byte(s) #{str(packet)}")

        def on_sendto(test_sock, data, address):
            p = Packet.parse_packet_bytes(data)
            plog = str(p)
            logging.debug(f"Sending: {plog} to {address}")

            if p.opcode == TftpOpCodes.RRQ:
                fname = f"{submission}_download_file-template.txt"
                injected = Packet.make_rrq(fname)
                logging.debug(f"[>] Sending: {injected} to {address}")
                assert test_sock.sendto_count == 1
                return (Packet.serialize_packet(injected), address)

            # ACK is the second packet to be sent when receiving data.
            if test_sock.sendto_count == 2:
                assert p.opcode == TftpOpCodes.ACK
                assert p.blk == 1
                test_sock.pass_ack = True
                raise TerminatePass()

        caplog.set_level(logging.DEBUG)
        socket_builder = fake_socket_factory(
            on_sendto=on_sendto, on_recvfrom=on_recvfrom, transparent=True)

        with context.ClientContext.from_submission(submission) as ctx:
            download_scenario = runner.ClientScenario.download_file(
                ctx.module_path,
                ctx.download_template
            )
            with monkeypatch.context() as m:
                m.setattr(socket, "socket", socket_builder)
                try:
                    run = download_scenario.run()
                except TerminatePass:
                    pass


# TODO: make a test for using select/asyncio
# def test_uses_select(self, caplog, monkeypatch, submission):
#     """
#     Test that the code sends an ACK after the first data
#     """

#     caplog.set_level(logging.DEBUG)


# @pytest.mark.timeout(TEST_TIMEOUT)
# @pytest.mark.parametrize('submission', submissions_iter, ids=submission.get_test_id)
# def test_exp_writing_correct_data(caplog, monkeypatch, submission):
#     caplog.set_level(logging.DEBUG)
#     ffd_builder, fake_fd = fake_open_fd_factory()

#     def on_read(n=-1):
#         logging.debug("ON READ")
#         pass

#     def on_write(s):
#         logging.debug(f"ON WRITE [{s}]")
#         pass

#     fake_fd.on_read = on_read
#     fake_fd.on_write = on_write

#     with context.ClientContext.from_submission(submission) as ctx:
#         with monkeypatch.context() as m:
#             m.setattr(builtins, "open", ffd_builder)
#             upload_scenario = runner.ClientScenario.upload_file(
#                 ctx.module_path,
#                 ctx.upload_template
#             )

#             try:
#                 run = upload_scenario.run()
#             except TerminatePass:
#                 logging.debug("Passed")
