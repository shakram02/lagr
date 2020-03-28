import shlex 
import subprocess
from pathlib import Path
import os
from .config import CONFIG
from contextlib import ContextDecorator

def cmd_init_tftp_server():
    cmd = shlex.split("service tftpd-hpa restart")
    return cmd

class ClientScenario:

    SUBMISSIONS_PATH_ROOT = CONFIG['submission_dir_full_path']
    FILE_DOWNLOAD_NAME = CONFIG['template_file_name']

    @classmethod
    def download_file(cls, *args, **kwargs):
        cls.action = 'pull'
        return cls(*args, **kwargs)

    @classmethod
    def upload_file(cls, *args, **kwargs):
        cls.action = 'push'
        return cls(*args, **kwargs)

    def __init__(self, module_name):
        self.module_name = module_name

    def cmd_action(self,):
        cmd = shlex.split("python {module_path} 127.0.0.1 {action} {filename}".format(
            filename=self.FILE_DOWNLOAD_NAME,
            module_path=Path(self.full_module_path),
            action =self.action
        ))
        print(cmd)
        return cmd
    
    @property
    def full_module_path(self):
        return os.path.join(self.SUBMISSIONS_PATH_ROOT, self.module_name)
    
    def run(self):
        run_cmd(cmd_init_tftp_server()) and run_cmd(self.cmd_action())


def run_cmd(cmd):
    print("RUNNING CMD > {}".format(cmd))
    return subprocess.run(cmd,)

if __name__ == '__main__':
    file_download_scenario = ClientScenario.download_file('4614_4651_lab1\ -\ Khaled\ Gewily.py')
    file_download_scenario.run()