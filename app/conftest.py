import pytest
import logging


@pytest.fixture(autouse=True)
def set_loglevel(caplog):
    """
    Use it to ensure log level at the start of each test
    regardless of dvc.logger.setup(), Repo configs or whatever.
    """
    caplog.set_level(logging.DEBUG)
