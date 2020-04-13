from app.lab1.test_client import context, runner
import app.lib.submission as submission
import app.lab1.test_client as test_client
import sys
import os
import pytest
import shlex
import subprocess
import socket
import logging

sys.path.insert(0, os.getcwd())
cmd = shlex.split("sudo service tftpd-hpa restart")
subprocess.run(cmd, check=True)


config = test_client.config.CONFIG
code_directory = config['submission_dir_full_path']

# Assert that our paths and config are correct.
assert os.path.isdir(code_directory), f"{code_directory} doesn't exist."
assert len(os.listdir(code_directory)) != 0

submissions = submission.submissions_from_directory(code_directory)
submissions_iter = sorted(list(submissions), key=lambda s: s.module_path)
# test_module_path = "/workspaces/2020-lab1/app/lab1/submissions/2020/1111_2222_lab1.py"
# submissions_iter = [submission.Submission.from_module_path(test_module_path)]


def get_test_id(submission_val):
    return str(submission_val)


def get_file_not_found_error(file_name):
    return f"File not found. [{file_name}]"


@pytest.mark.timeout(3)
@pytest.mark.parametrize('submission', submissions_iter, ids=get_test_id)
def test_download_file(caplog, monkeypatch, submission):
    with context.ClientContext.from_submission(submission) as ctx:
        assert os.path.isfile(
            ctx.download_template), "Downloadable file doesn't exist."
        assert os.path.isfile(
            ctx.module_path), f"Couldn't find module {ctx.module_path}"

        download_scenario = runner.ClientScenario.download_file(
            ctx.module_path,
            ctx.download_template
        )
        try:
            run = download_scenario.run()
        except SystemExit:
            print("Submission called: sys.exit()")

        ctx.check_downloaded_file()


@pytest.mark.timeout(3)
@pytest.mark.parametrize('submission', submissions_iter, ids=get_test_id)
def test_upload_file(submission):
    with context.ClientContext.from_submission(submission) as ctx:
        ctx = context.ClientContext.from_submission(submission)
        upload_scenario = runner.ClientScenario.upload_file(
            ctx.module_path,
            ctx.upload_template
        )

        try:
            run = upload_scenario.run()
        except SystemExit:
            print("Submission called: sys.exit()")

        ctx.check_uploaded_file()
