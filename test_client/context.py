import contextlib
import tempfile
import shutil
import os
from .config import CONFIG

def get_cwd_file_path(filename):
    cwd = CONFIG['submission_dir_full_path']
    return os.path.join(cwd, filename)

def get_server_cwd_file_path(filename):
    cwd = '/srv/tftp'
    return os.path.join(cwd,filename)

class ClientContext:
    FILE_TEMPLATE_NAME = 'file-template.txt'
    FILE_TEMPLATE_PATH = os.path.join(CONFIG['static_files_path'], FILE_TEMPLATE_NAME)
    @classmethod
    def from_submission(cls, submission):
        module_path = submission.module_path
        file_prefix = str(submission)
        return cls(module_path=module_path, file_prefix=file_prefix)

    def __init__(self, module_path, file_prefix):
        self.module_path = module_path 
        self.file_prefix = file_prefix
        download_file_name = file_prefix + '_download_' + self.FILE_TEMPLATE_NAME
        upload_file_name = file_prefix + '_upload_' + self.FILE_TEMPLATE_NAME
        self.downloadable_file = get_server_cwd_file_path(download_file_name)
        self.uploadable_file = get_cwd_file_path(upload_file_name)

        self.downloaded_file = get_cwd_file_path(download_file_name)
        self.uploaded_file = get_server_cwd_file_path(upload_file_name)
    
    
    def render_file_templates(self,):
        self._do_render_file_templates(self.uploadable_file)
        self._do_render_file_templates(self.downloadable_file)
    
    def _do_render_file_templates(self, target_path):
        shutil.copy(self.FILE_TEMPLATE_PATH, target_path)

    @staticmethod
    def _do_remove_file(file, catch_exception=False):
        try:
            os.remove(file)
        except FileNotFoundError as err:
            if catch_exception:
                pass
            else:
                raise(err)

    def __enter__(self):
        self.render_file_templates()
        return self

    def __exit__(self, excpetion_type, excetion_value, traceback):
        self._do_remove_file(self.downloadable_file)
        self._do_remove_file(self.uploadable_file)
        # Remove file of side effects that were downloaded and uploaded
        self._do_remove_file(self.downloaded_file, catch_exception=True)
        self._do_remove_file(self.uploaded_file, catch_exception=True)



if __name__ == '__main__':
    from __init__ import Submission
    import runner

    module_name = '4767_Lab1\ -\ Omar\ Reda.py' 
    module_path = os.path.join(CONFIG['submission_dir_full_path'], module_name)
    submission = Submission.from_module_path(module_path)

    with ClientContext.from_submission(submission) as ctx:
        download_scenario =  runner.ClientScenario.download_file(ctx.module_path, ctx.downloadable_file)
        download_scenario.run()