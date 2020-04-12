import shlex
from pathlib import Path
import os
import traceback
import runpy
from contextlib import ContextDecorator
from .config import CONFIG


class ClientScenario:

    SUBMISSIONS_PATH_ROOT = CONFIG['submission_dir_full_path']
    FILE_DOWNLOAD_NAME = CONFIG['test_file_name']

    @staticmethod
    def download_file(module_path, downloadable_file):
        return ClientScenario(module_path, downloadable_file, "pull")

    @staticmethod
    def upload_file(module_path, uploadable_file):
        return ClientScenario(module_path, uploadable_file, "push")

    def __init__(self, module_path, file_path, action):
        self.module_path = module_path
        self.file_path = file_path
        self.action = action

    @property
    def file_name(self):
        return os.path.split(self.file_path)[1]

    def run(self):
        import sys
        sys.argv = []
        sys.argv.append("placeholder")
        sys.argv.append('127.0.0.1')
        sys.argv.append(self.action)
        sys.argv.append(self.file_name)
        init_globals = {'sys': sys}
        module_runner = run_module(
            str(self.module_path),
            init_globals,
        )

        return module_runner()


def run_module(module_path, init_globals):
    def lazy_execution():
        run_name = '__main__'
        runpy.run_path(
            module_path,
            init_globals=init_globals,
            run_name=run_name)
    return lazy_execution


# if __name__ == '__main__':
#     module_name ='4614_4651_lab1\ -\ Khaled\ Gewily.py'
#     module_path = os.path.join(CONFIG['submission_dir_full_path'], module_name)
#     file_path = os.path.join(os.getcwd(), CONFIG['test_file_name'])

#     file_download_scenario = ClientScenario.download_file(module_path=module_path, file_path=file_path)
#     file_download_scenario.run()

#     file_upload_scenario = ClientScenario.upload_file(module_path=module_path, file_path=file_path)
#     file_upload_scenario.run()
