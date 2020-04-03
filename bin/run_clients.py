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
        with context.ClientContext.from_submission(submission) as ctx:
            download_scenario = runner.ClientScenario.download_file(
                ctx.module_path,
                ctx.downloadable_file
            )
            download_scenario.run()