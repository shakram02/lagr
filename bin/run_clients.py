import sys 
import os

sys.path.insert(0, os.getcwd())

import test_client
from test_client import context, runner

if __name__ == '__main__':
    config = test_client.config.CONFIG
    submissions_iter = test_client.submissions_from_directory(
        config['submission_dir_full_path']
    )
    for submission in submissions_iter:
        ctx = context.ClientContext.from_submission(submission)
        with test_client.grader.Grader(ctx) as grdr: 
            grdr.register(test_client.grader.expect_wrong_socket)
            download_scenario = runner.ClientScenario.download_file(
                ctx.module_path,
                ctx.downloadable_file
            )
            upload_scenario = runner.ClientScenario.upload_file(
                ctx.module_path,
                ctx.uploadable_file,
            )
            run = download_scenario.run()
            pass