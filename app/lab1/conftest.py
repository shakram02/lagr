# from typing import Dict, Tuple
# import pytest
# import _pytest
# import logging
# # source: https://docs.pytest.org/en/latest/example/simple.html
# # store history of failures per test class name and per index in parametrize (if parametrize used)
# _test_passed_children: Dict[str, Dict[Tuple[str, ...], str]] = {}

# # Avoid typos :'(
# INCR_KEYWORD = "incremental"
# SUBMISSION_KEYWORD = "submission"
# PARENT_KEYWORD = "parent"
# CHILD_KEYWORD = "child"


# def get_test_name(test: pytest.Item) -> str:
#     return test.originalname or test.name


# class SubmissionTestInstance(object):
#     def __init__(self, parent, submission_identifier):
#         self.submission_identifier = submission_identifier
#         self.children_names = set()
#         self.children = []
#         self.parent_success = False
#         self.parent = parent

#     def add_child(self, test: pytest.Item):
#         test_name = get_test_name(test)
#         if test_name in self.children_names:
#             return

#         self.children.append(test)
#         self.children_names.add(test_name)

#     def set_parent_success(self, parent_success):
#         self.parent_success = parent_success

#     def parent_name(self):
#         return get_test_name(self.parent)


# class TestTree(object):
#     def __init__(self, parent):
#         self.parent = parent
#         self.children = {}  # Perserve ordering.

#     def add_parent(self, test: pytest.Item, submission_identifier):
#         test_instance = SubmissionTestInstance(test, submission_identifier)
#         self.children[submission_identifier] = test_instance

#     def add_child(self, test: pytest.Item, submission_identifier):
#         test_instance = self.children[submission_identifier]
#         test_instance.add_child(test)

#     def set_parent_success(self, submission_identifier, parent_success):
#         test_instance = self.children[submission_identifier]
#         test_instance.set_parent_success(parent_success)

#     def has_successful_parent(self, submission_identifier):
#         return self.children[submission_identifier].parent_success


# current_tree: TestTree = None


# @pytest.hookimpl(tryfirst=True, hookwrapper=True)
# def pytest_runtest_makereport(item: pytest.Item, call: _pytest.runner.CallInfo):
#     outcome = yield
#     outcome = outcome.get_result()

#     # We're not interested in doing anything before running the test.
#     if outcome.when == "setup":
#         return

#     print("\nTEST [report]", get_test_name(item), outcome.outcome)
#     # if outcome.passed:
#     #     print("Skipped.")

# #     print("\nTEST [makereport]:", get_test_name(item))
# #     return

#     # if CHILD_KEYWORD in item.keywords:
#     #     print("ITEM SUB:", item.submission)
#     #     submission_name = str(item.funcargs[SUBMISSION_KEYWORD])
#     #     current_tree.add_child(item, submission_name)

#     # if PARENT_KEYWORD in item.keywords:
#     #     submission_name = str(item.funcargs[SUBMISSION_KEYWORD])
#     #     current_tree.add_parent(item, submission_name)
#     #     # Parent failed, continue normally.
#     #     # Don't add the parent to dictionary.
#     #     if call.excinfo is None:
#     #         current_tree.set_parent_success(submission_name, True)
#     #     else:
#     #         current_tree.set_parent_success(submission_name, False)


# def pytest_runtest_setup(item: pytest.Item):
#     print("\nTEST [setup]:", get_test_name(item))
#     pytest.skip()
#     return
#     # Parent will always run.
#     if PARENT_KEYWORD in item.keywords:
#         submission = item.callspec.params[SUBMISSION_KEYWORD]
#         # print("PARAM INDEX:", )
#         current_tree = TestTree(item)
#         return

#     # retrieve the class name of the test
#     cls_name = get_test_name(item)
#     submission = item.callspec.params[SUBMISSION_KEYWORD]
#     item.submission = submission

#     pytest.skip()
#     # if current_tree.has_successful_parent(str(submission)):
#     #     skip_msg = f"[{cls_name}] Parent succeeded. [{submission}]"
#     #     # print(skip_msg)
#     #     pytest.skip(skip_msg)

#     # parametrize_index = (
#     # print("PARAM INDEX:", item.callspec.params[SUBMISSION_KEYWORD])
#     # if hasattr(item, "callspec")
#     # else ()
#     # )

#     # check if a previous test has failed for this class
#     # if current_tree.has_successful_parent():
#     #     # Parent succeeded, no need to proceed with the children.
#     #     skip_msg = f"[{cls_name}] Parent succeeded. [{current_tree.parent_name()}]"
#     #     pytest.skip(skip_msg)
#     #     return
