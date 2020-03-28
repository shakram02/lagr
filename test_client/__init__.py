import glob
import config


class Submission:
    @classmethod
    def from_module_name(cls, module_name,):
        first_id, second_id = cls.extract_ids(module_name)
        module_name = module_name
        return cls(module_name, first_id, second_id)

    def __init__(self, file_path, first_student, second_student):
        self.file_path = file_path
        self.first_student = first_student
        self.second_student = second_student

    @staticmethod
    def extract_ids(module_name):
        before_hyphen, _ = module_name.split('-')
        first_id, second_id, _ = before_hyphen.split('_')
        return first_id, second_id


def submissions_from_directory(submission_dir_full_path):
    return [
        Submission.from_module_name(module) 
        for module in glob.glob(submission_dir_full_path)
    ]