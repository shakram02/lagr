import threading
import logging
import sys
import traceback
from multiprocessing.connection import Connection
from app.lib.constants import *


class FakeThread(threading.Thread):
    def __init__(self, target=None, args=None, name=None, parent_pipe: Connection = None):
        self._parent_pipe = parent_pipe
        self.is_placeholder = target == None
        super().__init__(target=target, name=name, args=args)
        super().setDaemon(True)    # Die with your parent.

    def setDaemon(self, value):
        pass

    def run(self):
        """
        Overrides the default behaviour to run a thread.

        NOTE: when using this object; users are expected to call start()
        not run(). run() is to only be overridden, while start() is what
        must be called.
        """
        if self.is_placeholder:
            return

        try:
            self._target(*self._args, **self._kwargs)
            if self._parent_pipe:
                self._parent_pipe.send(None)
        except BaseException as e:
            e.tb = traceback.format_exc()
            if self._parent_pipe:
                self._parent_pipe.send(e)

            # line = f"CAUGHT: {type(e)} from child thread.\n\t{str(e)}"
            line = "Caught from thread."
            # exc_log = traceback.format_exc()
            # logging.debug(f"{ANSI_YELLOW}\n{line}\n{exc_log}{ANSI_RESET}\n")
            logging.debug(f"{ANSI_YELLOW}\n{line}{ANSI_RESET}\n")

    def join(self):
        if self.is_placeholder:
            return
        else:
            super().join()


def fake_thread_builder(run=None, child_connection=None):

    def thread_maker(target=None, args=None, name=None, group=None):
        nonlocal run
        if run != "*" and (not run or target.__name__ not in run):
            # A thread that won't run
            return FakeThread()

        # For the amazing students who pass the target as a function call
        # not a function pointer.
        if not target:
            tb_obj = traceback.extract_stack()[3]
            line = str(tb_obj.line)
            location = f"{tb_obj.filename} line: {tb_obj.lineno}"
            raise ValueError(
                f"[ERROR] Invalid thread target (function reference required) in:\n\"{line}\" in {location}")
        target_name = f"BAD [{target}]" if not target else target.__name__
        logging.debug(f"RUN: {target_name}")
        return FakeThread(target=target, args=args, parent_pipe=child_connection)

    return thread_maker


class MiniFakeThread():
    def __init__(self, target, args):
        self.target = target
        self.args = args

    def start(self):
        self.target(*self.args)

    def setDaemon(self, _):
        pass

    def join(self, timeout=None):
        pass


def no_thread_builder():
    def f(target=None, args=None, name=None, group=None):
        return MiniFakeThread(target, args)

    return f
