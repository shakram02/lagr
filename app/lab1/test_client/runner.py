import shlex 
import subprocess
from pathlib import Path
import os
import traceback
import runpy
from contextlib import ContextDecorator
from .config import CONFIG

def cmd_init_tftp_server():
    cmd = shlex.split("service tftpd-hpa restart")
    return cmd

class ClientScenario:

    SUBMISSIONS_PATH_ROOT = CONFIG['submission_dir_full_path']
    FILE_DOWNLOAD_NAME = CONFIG['test_file_name']

    @classmethod
    def download_file(cls, *args, **kwargs):
        kwargs['action'] = "pull"
        return cls(*args, **kwargs)

    @classmethod
    def upload_file(cls, *args, **kwargs):
        kwargs['action'] = "push"
        return cls(*args, **kwargs)

    def __init__(self, module_path, file_path, action):
        self.module_path = module_path
        self.file_path = file_path
        self.action = action

    def cmd_action(self,):
        import sys
        sys.argv = []
        sys.argv.append("placeholder")
        sys.argv.append('127.0.0.1')
        sys.argv.append(self.action)
        sys.argv.append(self.file_name)
        init_globals = {'sys': sys}
        return run_module(
            str(self.module_path),
            init_globals,
        )
    
    @property
    def module_path_escaped(self):
        return str(self.module_path).replace(' ', '\ ')

    @property
    def file_name(self):
        return os.path.split(self.file_path)[1]

    def run(self):
        run_cmd(cmd_init_tftp_server()) 
        return self.cmd_action()()


def run_cmd(cmd):
    print("RUNNING CMD > {}".format(cmd))
    try:
        comp =  subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as err:
        tb = traceback.format_exc()
        print(tb)

def run_module(module_path, init_globals):
    def lazy_execution():
        run_name = '__main__'
        runpy.run_path(
            module_path, 
            init_globals=init_globals,
            run_name=run_name)
    return lazy_execution


if __name__ == '__main__':
    module_name ='4614_4651_lab1\ -\ Khaled\ Gewily.py' 
    module_path = os.path.join(CONFIG['submission_dir_full_path'], module_name)
    file_path = os.path.join(os.getcwd(), CONFIG['test_file_name'])

    file_download_scenario = ClientScenario.download_file(module_path=module_path, file_path=file_path)
    file_download_scenario.run()

    file_upload_scenario = ClientScenario.upload_file(module_path=module_path, file_path=file_path)
    file_upload_scenario.run()
