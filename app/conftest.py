import pytest
import logging


@pytest.fixture(autouse=True)
def set_loglevel(caplog):
    """
    Use it to ensure log level at the start of each test.
    """
    caplog.set_level(logging.DEBUG)
