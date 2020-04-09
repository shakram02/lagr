from test_client import context, runner
import submission
import test_client
import sys
import os
import pytest
import signal

sys.path.insert(0, os.getcwd())


config = test_client.config.CONFIG
submissions_iter = list(submission.submissions_from_directory(
    config['submission_dir_full_path']))


def get_test_id(submission_val):
    return str(submission_val)


@pytest.mark.timeout(3)
@pytest.mark.parametrize('submission', submissions_iter, ids=get_test_id)
def test_download_file(submission):
    with context.ClientContext.from_submission(submission) as ctx:
        download_scenario = runner.ClientScenario.download_file(
            ctx.module_path,
            ctx.downloadable_file
        )
        run = download_scenario.run()
        assert os.path.isfile(ctx.downloaded_file)


@pytest.mark.timeout(3)
@pytest.mark.parametrize('submission', submissions_iter, ids=get_test_id)
def test_upload_scenario(submission):
    with context.ClientContext.from_submission(submission) as ctx:
        ctx = context.ClientContext.from_submission(submission)
        upload_scenario = runner.ClientScenario.upload_file(
            ctx.module_path,
            ctx.uploadable_file
        )
        run = upload_scenario.run()
        assert os.path.isfile(ctx.uploadable_file)
