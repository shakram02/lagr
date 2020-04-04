# Define exception handling and extraction 
import contextlib


#TODO: better interface

@contextlib.contextmanager
def expect_wrong_socket():
    try:
        yield
    except OSError as err:
        #TODO: csv writer to capture the state of error
        pass

class Grader(contextlib.ExitStack):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.enter_context(ctx)
    
    def register(self, resolver):
        self.enter_context(resolver())