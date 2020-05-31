import multiprocessing as mp
import traceback
import logging
import sys
import tempfile
from app.lib.fake_stream import ProcessOutputStream
from app.lib.constants import *


class WrappedProcess(mp.Process):
    PROCESS_TIMEOUT = 0.5
    """
    Wraps a child process and catches its stdout, stderr and any raised exceptions.
    
    https://stackoverflow.com/questions/19924104/python-multiprocessing-handling-child-errors-in-parent
    """

    def __init__(self, *args, **kwargs):
        mp.Process.__init__(self, *args, **kwargs)
        # TODO: use Queue https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Queue
        self._parent_conn, self._child_conn = mp.Pipe()
        self._exception = None
        self.msgs = None
        self._sys_err = ProcessOutputStream()
        self._sys_out = ProcessOutputStream()

    def join(self, timeout=None):
        if not timeout:
            timeout = WrappedProcess.PROCESS_TIMEOUT

        mp.Process.join(self, timeout)

    def run(self):
        """
        Overrides the default behaviour to run a process.

        NOTE: when using this object; users are expected to call start()
        not run(). run() is to only be overridden, while start() is what
        must be called.
        """
        # Exceptions will be raised from the hooked
        # socket functions. Which we'll receive
        # here and re-raise in our "Process", as
        # by default processes don't know about
        try:
            self._target(*self._args, **self._kwargs)
            self._child_conn.send(None)
        except BaseException as e:
            e.tb = traceback.format_exc()
            self._child_conn.send(e)
            # Just to not forget that the process catches its
            # child exceptions.
            line = "Caught from subprocess."
            # line = f"CAUGHT: {type(e)} from subprocess.\n\t{str(e)}"
            logging.debug(f"{ANSI_YELLOW}\n{line}{ANSI_RESET}\n")
            # raise e  # You can still rise this exception if you need to

    @property
    def exception(self):
        if self._parent_conn.poll():
            self._exception = self._parent_conn.recv()
        return self._exception

    @property
    def all_child_messages(self):
        if self.msgs is not None:
            return self.msgs
        else:
            self.msgs = []

        while self._parent_conn.poll():
            self.msgs.append(self._parent_conn.recv())

        return self.msgs

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
