import glob
import os
from pathlib import Path


class Submission:
    @staticmethod
    def from_module_path(module_path):
        module_name = os.path.split(module_path)[1]
        first_id, second_id = Submission.extract_ids(module_name)
        return Submission(module_path, first_id, second_id)

    def __init__(self, module_path, first_student, second_student):
        self.module_path = module_path
        self.first_student = first_student
        self.second_student = second_student

    def __str__(self):
        if self.second_student:
            return self.first_student + '_' + self.second_student
        else:
            return self.first_student

    def __repr__(self):
        mod_name = os.path.basename(self.module_path)
        return f"ID: {self.__str__()} @ FILE: {mod_name}"

    @staticmethod
    def extract_ids(module_name):
        try:
            before_hyphen, _ = module_name.split('-')
        except ValueError:
            before_hyphen = module_name

        splitted = before_hyphen.split('_')
        if len(splitted) > 2:
            first_id, second_id, _ = splitted
            return first_id, second_id
        elif len(splitted) == 2:
            first_id, _ = splitted
            return first_id, ''


def submissions_from_directory(submission_dir):
    paths = Path(submission_dir).resolve().glob("*.py")
    for module_path in filter(lambda path: path.is_file, paths):
        yield Submission.from_module_path(module_path)


def get_test_id(submission: Submission):
    return str(submission)
