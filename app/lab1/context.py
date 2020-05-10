import contextlib
import tempfile
import shutil
import os
from .config import CONFIG
import app.lib.error_msgs as error_msgs
import subprocess
import shlex
import pwd
import grp
import glob
uid = pwd.getpwnam("tftp").pw_uid
gid = grp.getgrnam("tftp").gr_gid


def get_cwd_file_path(filename):
    cwd = os.getcwd()
    return os.path.join(cwd, filename)


def get_server_cwd_file_path(filename):
    cwd = '/srv/tftp'
    return os.path.join(cwd, filename)


class ServerContext:
    FILE_TEMPLATE_NAME = 'file-template.txt'
    SCRATCH_DISK_FOLDER = CONFIG['scratch_disk']
    FILE_TEMPLATE_PATH = os.path.join(
        CONFIG['static_files_path'], FILE_TEMPLATE_NAME)

    @staticmethod
    def from_submission(submission, test_name=None):
        if not test_name:
            test_name = ""

        module_path = submission.module_path
        file_prefix = str(submission) + test_name
        # Make a new ClientContext, with the given module path (submission)
        # since all submissions are modules.
        return ServerContext(module_path, file_prefix)

    def __init__(self, module_path, file_prefix):
        test_file_name = file_prefix + '_template_' + self.FILE_TEMPLATE_NAME
        self.module_path = module_path
        self.template_file = os.path.join(
            self.SCRATCH_DISK_FOLDER, test_file_name)

        # Downloaded/Uploaded file path after running the test case.
        done_file_name = file_prefix + '_complete_' + self.FILE_TEMPLATE_NAME
        self.done_file = get_cwd_file_path(done_file_name)

        self.file_length = os.path.getsize(self.FILE_TEMPLATE_PATH)

    def render_file_template(self):
        shutil.copy(self.FILE_TEMPLATE_PATH, self.template_file)
        assert os.path.isfile(self.template_file)

    def check_file(self):
        err = error_msgs.get_file_not_found_error(self.done_file)
        assert os.path.isfile(self.done_file), err
        assert self.file_length == os.path.getsize(
            self.done_file), f"FILE CHECK: {self.file_length} ON DISK: {os.path.getsize(self.done_file)}"

    def _do_remove_file(self, target, catch_exception=False):
        try:
            os.remove(target)
        except Exception as exc:
            if catch_exception:
                pass
            else:
                raise exc

    def __enter__(self):
        self.render_file_template()
        return self

    # Tear down the test environment.
    def __exit__(self, excpetion_type, excetion_value, traceback):
        scratch_files = glob.glob(ServerContext.SCRATCH_DISK_FOLDER + "/*")
        _ = [os.remove(f) for f in scratch_files]

        self._do_remove_file(self.template_file, catch_exception=True)
        # Remove file of side effects that were downloaded and uploaded
        self._do_remove_file(self.done_file, catch_exception=True)


class ClientContext:
    """
    Test environment for TFTP client.
    """
    FILE_TEMPLATE_NAME = 'file-template.txt'
    FILE_TEMPLATE_PATH = os.path.join(
        CONFIG['static_files_path'], FILE_TEMPLATE_NAME)

    @classmethod
    def from_submission(cls, submission):
        # Make a new ClientContext, with the given module path (submission)
        # since all submissions are modules.
        module_path = submission.module_path
        file_prefix = str(submission)
        return cls(module_path=module_path, file_prefix=file_prefix)

    def __init__(self, module_path, file_prefix):
        # if os.geteuid() != 0:
        # exit("You need to have root privileges to run this code.\nPlease try again, this time using 'sudo'. Exiting.")

        self.module_path = module_path
        self.file_prefix = file_prefix
        download_file_name = file_prefix + '_download_' + self.FILE_TEMPLATE_NAME
        upload_file_name = file_prefix + '_upload_' + self.FILE_TEMPLATE_NAME
        self.download_template = get_server_cwd_file_path(download_file_name)
        self.upload_template = get_cwd_file_path(upload_file_name)

        # Downloaded/Uploaded file path after running the test case.
        self.downloaded_file = get_cwd_file_path(download_file_name)
        self.uploaded_file = get_server_cwd_file_path(upload_file_name)

        self.upload_template_length = os.path.getsize(self.FILE_TEMPLATE_PATH)
        self.download_template_length = os.path.getsize(
            self.FILE_TEMPLATE_PATH)
        # block on the last popen (popen completes async.)
        self.last_popen: subprocess.Popen = None

    # Make the files available to the code to be tested.
    def render_file_templates(self):
        self._render_download_template()
        self._do_render_file_templates(self.upload_template)

    def check_downloaded_file(self):
        err = error_msgs.get_file_not_found_error(self.downloaded_file)
        assert os.path.isfile(self.downloaded_file), err
        size_on_disk = os.path.getsize(self.downloaded_file)
        assert self.download_template_length == size_on_disk, f"FILE SIZE: {self.upload_template_length} ON DISK: {size_on_disk}"

    def check_uploaded_file(self):
        err = error_msgs.get_file_not_found_error(self.uploaded_file)
        assert os.path.isfile(self.uploaded_file), err
        size_on_disk = os.path.getsize(self.uploaded_file)
        assert self.upload_template_length == size_on_disk, f"FILE SIZE: {self.upload_template_length} ON DISK: {size_on_disk}"

    def _do_render_file_templates(self, target_path):
        shutil.copy(self.FILE_TEMPLATE_PATH, target_path)
        assert os.path.isfile(target_path)

    def _render_download_template(self):
        cmd = shlex.split(
            f"sudo cp {self.FILE_TEMPLATE_PATH} {self.download_template}")
        self.last_popen = subprocess.Popen(cmd)

        cmd = shlex.split(
            f"sudo chown tftp:tftp {self.download_template}")
        self.last_popen = subprocess.Popen(cmd)

        # shutil.copy(self.FILE_TEMPLATE_PATH, self.download_template)
        # os.chown(self.download_template, uid, gid)

    # Remove files after finishing the test
    def _do_remove_file(self, file, catch_exception=False):
        cmd = shlex.split(f"sudo rm {file}")
        self.last_popen = subprocess.Popen(cmd)

    # Setup the files to be used before running the test case.
    def __enter__(self):
        self.render_file_templates()
        self.last_popen.wait(3)
        return self

    # Tear down the test environment.
    def __exit__(self, excpetion_type, excetion_value, traceback):
        self._do_remove_file(self.download_template, catch_exception=True)
        self._do_remove_file(self.upload_template, catch_exception=True)
        # Remove file of side effects that were downloaded and uploaded
        self._do_remove_file(self.downloaded_file)
        self._do_remove_file(self.uploaded_file)
        self.last_popen.wait(3)


# if __name__ == '__main__':
#     from __init__ import Submission
#     import runner

#     module_name = '4767_Lab1\ -\ Omar\ Reda.py'
#     module_path = os.path.join(CONFIG['submission_dir_full_path'], module_name)
#     submission = Submission.from_module_path(module_path)

#     with ClientContext.from_submission(submission) as ctx:
#         download_scenario = runner.ClientScenario.download_file(
#             ctx.module_path, ctx.download_template)
#         download_scenario.run()
