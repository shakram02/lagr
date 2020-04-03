import glob
import os 
from pathlib import Path
from . import config


class Submission:
    @classmethod
    def from_module_path(cls, module_path,):
        print("Submission for path {}".format(module_path))
        module_name = os.path.split(module_path)[1]
        first_id, second_id = cls.extract_ids(module_name)
        return cls(module_path, first_id, second_id)

    def __init__(self, module_path, first_student, second_student):
        self.module_path = module_path
        self.first_student = first_student
        self.second_student = second_student
    
    def __str__(self):
        return self.first_student + '_' + self.second_student

    @staticmethod
    def extract_ids(module_name):
        before_hyphen, _ = module_name.split('-')
        splitted = before_hyphen.split('_')
        if len(splitted) > 2:
            first_id, second_id, _ = splitted
            return first_id, second_id
        elif len(splitted) == 2:
            first_id, _ = splitted
            return first_id, ''


def submissions_from_directory(submission_dir_full_path):
    dir_path = Path(submission_dir_full_path)
    for module_path in dir_path.iterdir():
        yield Submission.from_module_path(module_path)