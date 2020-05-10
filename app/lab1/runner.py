import shlex
from pathlib import Path
import os
import traceback
import runpy
from contextlib import ContextDecorator
from .config import CONFIG
import subprocess
import multiprocessing
import sys
from app.lib.wrapped_process import WrappedProcess
pytest_stderr = sys.stderr
pytest_stdout = sys.stdout


class ServerScenario:
    SUBMISSION_MODULE_PORT = 45543
    SUBMISSION_MODULE_IP = "127.0.0.1"
    @staticmethod
    def download_file_scenario(module_path, target_file):
        return ServerScenario(module_path, target_file, "get")

    @staticmethod
    def upload_file_scenario(module_path, target_file):
        return ServerScenario(module_path, target_file, "put")

    def __init__(self, module_path, target_file, action):
        self.module_path = module_path
        self.target_file = target_file
        self.action = action

    def establish_client_run_env(self, template_name):
        """
        The client is started in a process since we don't
        want to wait as long as TFTP wants.
        """
        cmd = self._make_tftp_cmd(self.action, template_name, self.target_file)

        def run_client(cmd):
            subprocess.run(["tftp"], input=cmd, encoding="ascii")

        p = WrappedProcess(target=run_client, args=(cmd,))
        p.daemon = True
        return p

    def _make_tftp_cmd(self, action, template_name, target_file):
        file_name = os.path.split(target_file)[1]
        # Pipe TFTP commands into the program's stdin.
        connect_cmd = f"connect {ServerScenario.SUBMISSION_MODULE_IP} {ServerScenario.SUBMISSION_MODULE_PORT}"
        c = f"verbose\r\nmode octet\r\ntrace\r\ntimeout 1\r\n{connect_cmd}" +\
            f"\r\n{action} {template_name} {file_name}\r\nquit\r\n"

        return c

    def establish_server_run_env(self):
        """
        The server is started in a process so we can
        terminate it in the test.

        Because if two tests run consecutively and
        we leave the server open, the second attempt
        to bind the socket in the second test will fail.

        This happens because we have no method to control the
        run_module function.

        We are using processes because we can't kill threads.
        """
        import sys  # patched sys (as the test already started)
        sys.argv = []
        sys.argv.append("placeholder")
        sys.argv.append(ServerScenario.SUBMISSION_MODULE_IP)
        sys.argv.append(str(ServerScenario.SUBMISSION_MODULE_PORT))
        init_globals = {'sys': sys}

        runner = run_module(str(self.module_path), init_globals)
        p = WrappedProcess(target=runner)
        p.daemon = True
        return p


class ClientScenario:
    FILE_DOWNLOAD_NAME = CONFIG['test_file_name']

    @staticmethod
    def download_file(module_path, downloadable_file):
        return ClientScenario(module_path, downloadable_file, "pull")

    @staticmethod
    def upload_file(module_path, uploadable_file):
        return ClientScenario(module_path, uploadable_file, "push")

    def __init__(self, module_path, file_path, action):
        self.module_path = module_path
        self.file_path = file_path
        self.action = action

    def run(self):
        import sys  # patched sys (as the test already started)
        sys.argv = []
        sys.argv.append("placeholder")
        sys.argv.append('127.0.0.1')
        sys.argv.append(self.action)

        target_file_name = os.path.split(self.file_path)[1]
        sys.argv.append(target_file_name)
        init_globals = {'sys': sys}

        module_runner = run_module(
            str(self.module_path),
            init_globals,
        )

        return module_runner()


def run_module(module_path, init_globals):
    def lazy_execution():
        run_name = '__main__'
        runpy.run_path(
            module_path,
            init_globals=init_globals,
            run_name=run_name)
    return lazy_execution


# if __name__ == '__main__':
#     module_name ='4614_4651_lab1\ -\ Khaled\ Gewily.py'
#     module_path = os.path.join(CONFIG['submission_dir_full_path'], module_name)
#     file_path = os.path.join(os.getcwd(), CONFIG['test_file_name'])

#     file_download_scenario = ClientScenario.download_file(module_path=module_path, file_path=file_path)
#     file_download_scenario.run()

#     file_upload_scenario = ClientScenario.upload_file(module_path=module_path, file_path=file_path)
#     file_upload_scenario.run()
