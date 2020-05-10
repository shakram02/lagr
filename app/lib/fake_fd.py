import sys
import logging
import builtins
# Keep an un-patched method reference to be
# used by other system modules using open.
# we'll dynamically patch depending on the
# file that's calling open.
upatched_open = builtins.open
submission_directory = None


def setup_fake_fd_module(cur_dir):
    global submission_directory
    submission_directory = cur_dir


class FakeFd(object):
    def __init__(self):
        self.content = None
        self.on_write = None
        self.on_read = None

    def open(self, file, mode="rb", newline=""):
        logging.debug(f"OPEN [{mode}]: {file}")
        self.file = file
        self.mode = mode
        self.newline = newline
        return self

    def write(self, data):
        logging.debug(f"WRITE: {len(data)} bytes")
        if self.content is None:
            self.content = data
        else:
            self.content += data
        if self.on_write is not None:
            ret = self.on_write(data)
            if not ret:
                return len(data)

        raise NotImplementedError("Write operation shouldn't be used.")

    def read(self,  n=-1):
        logging.debug(f"READ")

        if self.on_read is not None:
            return self.on_read(n)

        raise NotImplementedError("Read operation shouldn't be used.")

    def close(self):
        pass

    def flush(self):
        pass

    def __enter__(self):
        logging.debug("ENTER file context")
        return self

    def __exit__(self, type, value, traceback):
        logging.debug("EXIT file context")


def fake_open_fd_factory():
    ffd = FakeFd()

    def fake_open(file, mode="rb", newline=''):
        caller_module_path: str = sys._getframe().f_back.f_code.co_filename

        if caller_module_path.startswith(submission_directory):
            # Double check config is correct.
            assert submission_directory is not None
            # Return the function to be used by the
            # patched code.
            return ffd.open(file, mode, newline)
        else:
            # System modules.
            return upatched_open(file, mode)

    return fake_open, ffd
