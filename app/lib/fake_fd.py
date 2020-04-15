import sys
import logging
import builtins
# Keep an un-patched method reference to be
# used by other system modules using open.
# we'll dynamically patch depending on the
# file that's calling open.
upatched_open = builtins.open
code_directory = None


def setup_fake_fd_module(cur_dir):
    global code_directory
    code_directory = cur_dir


class FakeFd(object):
    def __init__(self, file, mode="rb"):
        logging.debug(f"OPEN [{mode}]: {file}")

    def write(self, data):
        logging.debug(f"WRITE: {len(data)} bytes")
        return len(data)

    def read(self):
        logging.debug(f"READ: []")
        return []

    def close(self):
        pass

    def __enter__(self):
        logging.debug("ENTER file context")
        
        return self

    def __exit__(self, type, value, traceback):
        logging.debug("EXIT file context")


def fake_open_fd_factory(file, mode="rb", newline=''):
    caller_module_path: str = sys._getframe().f_back.f_code.co_filename

    # Submission
    if caller_module_path.startswith(code_directory):
        assert code_directory is not None
        return FakeFd(file, mode)

    # System modules.
    return upatched_open(file, mode)
