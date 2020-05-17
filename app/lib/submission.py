import glob
import os
import ast
import logging
from pathlib import Path
from typing import List


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


class CompiledSumbission(Submission):
    @staticmethod
    def from_submission(submission: Submission):
        return CompiledSumbission(submission.module_path, submission.first_student, submission.second_student)

    def __init__(self, module_path, first_student, second_student):
        super().__init__(module_path, first_student, second_student)

    def load_module_definitions(self):
        """
        Loads module definitions (classes/functions/imports)
        without executing the module itself. - i.e. doesn't run main() -
        NOTE: this requires that the code follows the template exactly.
        """
        with open(self.module_path) as code_fp:
            tree = ast.parse(code_fp.read())

            cleaned_up = ast.Module(body=[])
            for node in tree.body:
                # We don't want to execute loose code under if __name__ == "__main__"
                # or whatever. We just need the function definitions.
                if type(node) in [ast.FunctionDef, ast.Import, ast.ImportFrom, ast.ClassDef]:
                    # pylint: disable=no-member
                    cleaned_up.body.append(node)

            cleaned_up = ast.fix_missing_locations(cleaned_up)
            # Use module path to get stack trace.
            code = compile(cleaned_up, filename=self.module_path, mode="exec")
            functions = {}
            exec(code, functions)
            self._functions = functions

    def __getattr__(self, name):
        """
        To keep the code clean, we won't expose
        the loaded module functions directly.

        We'll override getattr and use the
        loaded functions directly.
        """
        if name in self._functions:
            return self._functions[name]

        raise AttributeError(f"Method not found [{name}]")


def submissions_from_directory(submission_dir) -> List[Submission]:
    paths = Path(submission_dir).resolve().glob("*.py")
    submissions = []
    for module_path in filter(lambda path: path.is_file, paths):

        try:
            submission = Submission.from_module_path(str(module_path))
            submissions.append(submission)
        except TypeError:
            # Skip wrongly named submissions.
            logging.warning(f"Illegal file name: {module_path}")

    return sorted(submissions, key=lambda s: s.module_path)


def get_test_id(submission: Submission):
    return str(submission)
