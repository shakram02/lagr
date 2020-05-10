import multiprocessing as mp
import traceback
import logging
import sys
import tempfile
from app.lib.fake_stream import ProcessOutputStream

ANSI_RESET = "\u001B[0m"
ANSI_RED = "\u001B[31m"
ANSI_YELLOW = "\u001B[33m"
ANSI_LIGHT_YELLOW = "\u001B[36m"


class WrappedProcess(mp.Process):
    PROCESS_TIMEOUT = 0.5
    """
    Wraps a child process and catches its stdout, stderr and any raised exceptions.
    
    https://stackoverflow.com/questions/19924104/python-multiprocessing-handling-child-errors-in-parent
    """

    def __init__(self, *args, **kwargs):
        mp.Process.__init__(self, *args, **kwargs)
        self._parent_conn, self._child_conn = mp.Pipe()
        self._exception = None
        self._sys_err = ProcessOutputStream()
        self._sys_out = ProcessOutputStream()

    def join(self, timeout=None):
        if not timeout:
            timeout = WrappedProcess.PROCESS_TIMEOUT

        mp.Process.join(self, timeout)

    def run(self):
        # Exceptions will be raised from the hooked
        # socket functions. Which we'll receive
        # here and re-raise in our "Process", as
        # by default processes don't know about
        # each other's exceptions.
        sys.stdout = self._sys_out
        sys.sterr = self._sys_err
        try:
            mp.Process.run(self)
            self._child_conn.send(None)
        except BaseException as e:
            e.tb = traceback.format_exc()
            self._child_conn.send(e)
            # raise e  # You can still rise this exception if you need to

    @property
    def exception(self):
        if self._parent_conn.poll():
            self._exception = self._parent_conn.recv()
        return self._exception

    @property
    def has_exception(self):
        return self.exception != None

    @property
    def stdout(self):
        return self._sys_out.read()

    @property
    def stderr(self):
        return self._sys_err.read()

    def log_existing_process_output(self):
        line = "#"*50

        if self.stdout is not None:
            stdout_content = self._sys_out.cleanup()
            logging.debug(f"{ANSI_YELLOW}\n{line}\n[STDOUT]\n{line}{ANSI_RESET}\n" +
                          stdout_content + f"\n{ANSI_YELLOW}{line}{ANSI_RESET}")

        if self.stderr is not None:
            stderr_content = self._sys_err.cleanup()
            logging.debug(f"{ANSI_LIGHT_YELLOW}\n{line}\n[STDERR]\n{line}{ANSI_RESET}\n" +
                          stderr_content + f"\n{ANSI_LIGHT_YELLOW}{line}{ANSI_RESET}")

        # if self.exception is not None:
        #     tb = self.exception.tb
        #     logging.debug(f"{ANSI_RED}\n{tb}{ANSI_RESET}")
