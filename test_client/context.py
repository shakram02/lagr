import contextlib
import tempfile
import shutil
from config import CONFIG
import os


class ClientContext:
    @classmethod
    def from_submission(cls, submission):
        module_path = submission.module_path
        file_path = os.path.join(os.getcwd(), 'file-template.txt')
        cls(module_path=module_path, file_path=file_path)

    def __init__(self, module_path, file_path):
        self.module_path = module_path 
        self.file_path = file_path
    
    def stage_files(self):
        # TODO:
        # copy file to download to tftp's server dir
        # copy module to the temp dir
        # copy file to upload to root dir 
        pass
    
    def __enter__(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.download_file = tempfile.NamedTemporaryFile()
        self.upload_file = tempfile.NamedTemporaryFile()

    def __exit__(self):
        self.tempdir.__exit__()
        self.tempfile.__exit__()
    
    def stage_file(self, filepath):
        shutil.copyfile(filepath, self.tempdir)

from . import Submission
import runner

submission = Submission.from_module_path('/app/submissions/extracted/1234_4566 - test.py')

with ClientContext.from_submission(submission) as ctx:
    download_scenario =  runner.ClientScenario.download_file(submission.module_path)