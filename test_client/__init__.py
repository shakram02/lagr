import glob
import config
import os 


class Submission:
    @classmethod
    def from_module_path(cls, module_path,):
        module_name = os.path.split(module_path)[1]
        first_id, second_id = cls.extract_ids(module_name)
        return cls(module_path, first_id, second_id)

    def __init__(self, module_path, first_student, second_student):
        self.module_path = module_path
        self.first_student = first_student
        self.second_student = second_student

    @staticmethod
    def extract_ids(module_name):
        before_hyphen, _ = module_name.split('-')
        first_id, second_id, _ = before_hyphen.split('_')
        return first_id, second_id


def submissions_from_directory(submission_dir_full_path):
    return [
        Submission.from_module_path(module_path) 
        for module_path in glob.glob(submission_dir_full_path)
    ]