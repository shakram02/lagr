import glob
import os
import ast
import logging
from pathlib import Path
from typing import List
from app.lib.ast_helpers import WhileTrueNodeToBoundedForTransformer
import app.lib.helpers as helpers
import runpy
import re
student_id_re = re.compile(r"\d{4,}")


class Submission:
    @staticmethod
    def from_module_path(module_path):
        module_name = os.path.split(module_path)[1]
        student_ids = Submission.extract_ids(module_name)
        return Submission(module_path, student_ids)

    def __init__(self, module_path, student_ids):
        self.module_path = module_path
        self.student_ids = student_ids

    def __str__(self):
        return "_".join(self.student_ids)

    def __repr__(self):
        mod_name = os.path.basename(self.module_path)
        return f"ID: {self.__str__()} @ FILE: {mod_name}"

    @staticmethod
    def extract_ids(module_name):
        try:
            # some students put their ID in their email name :3
            # " - " is added by google forms
            if len(module_name.split(" - ")) == 2:
                module_name, _ = module_name.split(" - ")

            student_ids = student_id_re.findall(module_name)
            assert len(student_ids) > 0
        except AssertionError:
            raise helpers.ModuleNameError(module_name)

        return student_ids


class CompiledSumbission(Submission):
    """
    Loads only definitions from a given source file.
    Any expressions in the code that aren't a child
    of a definition are ignored. The remaining code
    is compiled and executed.

    Global variables and main() aren't executed.
    """
    @staticmethod
    def from_submission(submission: Submission):
        return CompiledSumbission(submission.module_path, submission.student_ids)

    def __init__(self, module_path, student_ids):
        super().__init__(module_path, student_ids)

    def load_module_definitions(self, execute_ast_after_parse=True):
        """
        Loads module definitions (classes/functions/imports)
        without executing the module itself. - i.e. doesn't run main() -
        NOTE: this requires that the code follows the template exactly.
        """

        # Don't load any global variables, load all definitions and all imports.
        loadables = [ast.FunctionDef, ast.Import, ast.ImportFrom, ast.ClassDef]
        self._load_with_collections(loadables=loadables)

        if execute_ast_after_parse:
            self.execute_module_ast()

    def load_everything_without_executing(self, execute_ast_after_parse=True):
        """
        NOTE: we're not using runpy in this case as we can't patch runpy
        module after it's running. i.e. when we want to patch functions
        in the submissions itself, runpy can't be used for that because
        the module would already be running.

        We don't want to execute loose code under
        if __name__ == "__main__" or whatever.        
        """
        self._load_with_collections(ignoreables=[ast.If])
        if execute_ast_after_parse:
            self.execute_module_ast()

    def _load_with_collections(self, loadables=None, ignoreables=None):
        if not loadables and not ignoreables:
            raise ValueError("Can't have both empty loadables and ignoreables")

        if loadables and ignoreables:
            raise ValueError("Can't have both loadables and ignoreables")

        code_fp = open(self.module_path)
        tree = ast.parse(code_fp.read(), filename=self.module_path)
        code_fp.close()

        # Fix compat with python 3.8
        cleaned_up = ast.parse("")
        for node in tree.body:
            # pylint: disable=no-member
            if loadables:
                if type(node) in loadables:
                    cleaned_up.body.append(node)
                else:
                    continue

            if ignoreables:
                if type(node) in ignoreables:
                    continue
                else:
                    cleaned_up.body.append(node)

        cleaned_up = ast.fix_missing_locations(cleaned_up)
        self.submission_ast = cleaned_up

    def execute_module_ast(self):
        # Use module path to get stack trace.
        code = compile(self.submission_ast,
                       filename=self.module_path, mode="exec")
        namespace = {}
        exec(code, namespace)
        self._attributes = namespace

    def replace_while_true_with_for(self, iter_count=1, replace_decendents=False):
        modified_ast = WhileTrueNodeToBoundedForTransformer(
            iter_count, replace_decendents).visit(self.submission_ast)
        modified_ast = ast.fix_missing_locations(modified_ast)
        self.submission_ast = modified_ast

    def monkeypatch(self, name, value):
        if name not in self._attributes:
            raise AttributeError()
        self._attributes[name] = value

    # def _concrete_getattr(self, name):

    def __getattr__(self, name):
        """
        To keep the code clean, we won't expose
        the loaded module functions directly.

        We'll override getattr and use the
        loaded functions directly.
        """
        if name in self._attributes:
            return self._attributes[name]


class NonRunningSubmission(Submission):
    """
    Represents a module that's fully loaded (globals + definitions)
    but without setting the run_name to __main__ so main() won't
    run on its own (unlike exec_module).
    """
    @staticmethod
    def from_submission(submission: Submission):
        return NonRunningSubmission(submission.module_path, submission.student_ids)

    def __init__(self, module_path, student_ids):
        super().__init__(module_path, student_ids)
        self._attributes = {}

    def load_without_execution(self):
        """
        Loads the module and executes global variable definitions.

        WARNING: use this function as close to callsite as
        possible since it might have global sockets binding
        to addresses which will crash the submission loader.
        """
        import importlib
        import sys  # patched sys (as the test already started)
        sys.argv = []
        sys.argv.append("placeholder")
        init_globals = {'sys': sys}

        self._attributes = runpy.run_path(self.module_path,
                                          init_globals=init_globals,
                                          run_name="not-main")

    def __getattr__(self, name):
        """
        To keep the code clean, we won't expose
        the loaded module functions directly.

        We'll override getattr and use the
        loaded functions directly.
        """
        if name in self._attributes:
            return self._attributes[name]

        raise AttributeError(f"Method not found [{name}]")


def submissions_from_directory(submission_dir) -> List[Submission]:
    paths = Path(submission_dir).resolve().glob("*.py")
    submissions = []
    # TODO: handle those who submit multiple times.
    for module_path in filter(lambda path: path.is_file, paths):
        try:
            submission = Submission.from_module_path(
                str(module_path))
            submissions.append(submission)
        except TypeError:
            # Skip wrongly named submissions.
            logging.warning(f"Illegal file name: {module_path}")
        except helpers.ModuleNameError as e:
            logging.warning(e)
    return sorted(submissions, key=lambda s: s.module_path)


def load_as_modules(submission_dir) -> List[CompiledSumbission]:
    def process_submission(sub):
        sub = CompiledSumbission.from_submission(sub)
        sub.load_module_definitions()
        return sub

    return load_using_func(submission_dir, process_submission)


def load_as_non_running(submission_dir) -> List[NonRunningSubmission]:
    def process_submission(sub):
        sub = NonRunningSubmission.from_submission(sub)
        return sub

    return load_using_func(submission_dir, process_submission)


def load_using_func(submission_dir, func):
    submissions = []
    for sub in submissions_from_directory(submission_dir):
        try:
            submissions.append(func(sub))
        except Exception as e:
            msg = f"\n[ERROR] failed to load submission [{sub}]\n{e}"
            logging.exception(msg)

    return submissions


def get_test_id(submission: Submission):
    return str(submission)
