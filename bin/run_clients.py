import sys 
import os
import pytest
import signal

sys.path.insert(0, os.getcwd())

import test_client
from test_client import context, runner

config = test_client.config.CONFIG
submissions_iter = list(test_client.submissions_from_directory(
    config['submission_dir_full_path']))

@pytest.fixture(autouse=True)
def timeout(func=None):
    def handler(signum, frame):
        raise TimeoutError
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(3)



@pytest.mark.parametrize('submission', submissions_iter)
def test_submission(submission):
    ctx = context.ClientContext.from_submission(submission)
    download_scenario = runner.ClientScenario.download_file(
        ctx.module_path,
        ctx.downloadable_file
    )
    upload_scenario = runner.ClientScenario.upload_file(
        ctx.module_path,
        ctx.downloadable_file
    )
    for scenario in [download_scenario, upload_scenario]:
        scenario.run()

@pytest.mark.parametrize('submission', submissions_iter)
def test_download_file(submission):
    with context.ClientContext.from_submission(submission) as ctx:
        download_scenario = runner.ClientScenario.download_file(
            ctx.module_path,
            ctx.downloadable_file
        )
        run = download_scenario.run()
        assert os.path.isfile(ctx.downloaded_file)

@pytest.mark.parametrize('submission', submissions_iter)
def test_upload_scenario(submission):
    with context.ClientContext.from_submission(submission) as ctx:
        ctx = context.ClientContext.from_submission(submission)
        upload_scenario = runner.ClientScenario.upload_file(
            ctx.module_path,
            ctx.downloadable_file
        )
        assert os.path.isfile(ctx.uploaded_file)
        run = upload_scenario.run()