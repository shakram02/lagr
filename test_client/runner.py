import shlex 
import subprocess
from pathlib import Path
import os
from contextlib import ContextDecorator
from .config import CONFIG

def cmd_init_tftp_server():
    cmd = shlex.split("service tftpd-hpa restart")
    return cmd

class ClientScenario:

    SUBMISSIONS_PATH_ROOT = CONFIG['submission_dir_full_path']
    FILE_DOWNLOAD_NAME = CONFIG['template_file_name']

    @classmethod
    def download_file(cls, *args, **kwargs):
        kwargs['action'] = "pull"
        return cls(*args, **kwargs)

    @classmethod
    def upload_file(cls, *args, **kwargs):
        kwargs['action'] = "push"
        return cls(*args, **kwargs)

    def __init__(self, module_path, file_path, action):
        self.module_path = str(module_path).replace(' ', '\ ')
        self.file_path = file_path
        self.action = action

    def cmd_action(self,):
        cmd = shlex.split("python {module_path} 127.0.0.1 {action} {filename}".format(
            filename=self.file_name,
            module_path=Path(self.module_path),
            action =self.action
        ))
        print(cmd)
        return cmd
    
    @property
    def file_name(self):
        return os.path.split(self.file_path)[1]

    def run(self):
        run_cmd(cmd_init_tftp_server()) 
        return run_cmd(self.cmd_action())


def run_cmd(cmd):
    print("RUNNING CMD > {}".format(cmd))
    return subprocess.run(cmd,)

if __name__ == '__main__':
    module_name ='4614_4651_lab1\ -\ Khaled\ Gewily.py' 
    module_path = os.path.join(CONFIG['submission_dir_full_path'], module_name)
    file_path = os.path.join(os.getcwd(), CONFIG['template_file_name'])

    file_download_scenario = ClientScenario.download_file(module_path=module_path, file_path=file_path)
    file_download_scenario.run()

    file_upload_scenario = ClientScenario.upload_file(module_path=module_path, file_path=file_path)
    file_upload_scenario.run()
