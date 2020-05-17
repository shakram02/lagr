import csv
import os
import numpy as np
import time
import sys
import matplotlib.pyplot as plt
from app_config import YEAR, ROOT_DIR
from pprint import pprint
import re
import string
test_submission_id_result_regex = re.compile(r"(test_\w+)\[(.*?)\]\s(\w+)")
st_tests = dict()


class TestResult(object):
    def __init__(self, name, student_id, result):
        self.name = name
        self.student_id = student_id
        self.result = result

    def __repr__(self):
        return f"{self.name}:{self.student_id}:{self.result}"

    def __str__(self):
        return self.__repr__()


def parse_test_log():
    # HACK: I'll just pipe pytest's to this process's std
    # and skip parsing whenever non matching output are available,
    # because blah!
    accumulator = {}
    for line in sys.stdin:
        # Break once failures are found
        if "= FAILURES =" in line:
            break
        if not line.strip():
            continue
        matches = test_submission_id_result_regex.findall(line)

        if not matches:
            continue

        [(case_name, st_ids, result)] = matches
        test_result = TestResult(case_name, st_ids, result)

        if st_ids not in accumulator:
            accumulator[st_ids] = [test_result]
        else:
            accumulator[st_ids].append(test_result)

    return accumulator


def parse_crash_details():
    crash_details = []
    for line in sys.stdin:
        if "= short test summary info =" in line:
            break
        line = [letter for letter in line if letter in string.printable]
        crash_details.append("".join(line))

    return crash_details


def parse_short_summary():
    summary_lines = []
    fail_term = "FAILED "
    for line in sys.stdin:
        if not line.startswith(fail_term):
            return summary_lines

        _, summary = line.split(fail_term)
        summary_lines.append(summary)

    return summary_lines


def write_report(accumulator: dict, file_path):
    csv_array = []
    passed_statistics = []
    for k in accumulator.keys():
        st_ids = k
        student_case_info = [["ID", k]]
        passed = 0
        total = 0
        for r in accumulator[st_ids]:
            total += 1
            student_case_info.append((r.name, r.result))
            if r.result == "PASSED":
                passed += 1
        passed_statistics.append(passed)
        csv_array.append(student_case_info)
        csv_array.append([["OK", passed], ["TOTAL", total]])
        csv_array.append([[]])

    arr = np.asarray(passed_statistics)
    mean = round(arr.mean(), 4)
    stdev = round(arr.std(), 4)

    csv_array.append([["AVG", mean], ["STDev", stdev]])
    print("\n".join([str(x) for x in passed_statistics]))

    with open(file_path, "w") as f:
        writer = csv.writer(f)
        for row in csv_array:
            writer.writerows(row)

    print("AVG", mean)


def write_log_file(result_dir, node_name, log_lines):
    node_path = os.path.join(result_dir, node_name)

    with open(node_path, "w") as log_file:
        log_file.writelines(log_lines)

    print(f"[LOG] File written: {node_name}")


def main():
    lab_number = sys.argv[1]
    grader_name = sys.argv[2]
    parent_result_dir = f"{ROOT_DIR}/results"

    # https://stackoverflow.com/a/29293030/4422856
    cmd_parent_exists = f"[ -d {parent_result_dir} ]"
    cmd_mkdir_result = f"sudo mkdir {parent_result_dir}"
    cmd_chown_result_dir = f"sudo chown $(whoami) {parent_result_dir}"
    cmd_mkdir_and_chown = f"{cmd_mkdir_result} && {cmd_chown_result_dir}"
    os.system(f"{cmd_parent_exists} || {cmd_mkdir_and_chown}")

    # Don't use ROOT_DIR because it starts at root directory.
    # mkdir -p won't work.
    result_dir = f"{ROOT_DIR}/results/{YEAR}/lab_{lab_number}/{grader_name}"
    timestamp = time.strftime("%d_%m_%Y_%H_%M_%S")

    print(f"[LOG] Root directory:", result_dir)
    os.system(f"sudo mkdir -p {result_dir}")
    os.system(f"sudo chown -R $(whoami) {parent_result_dir}")

    os.makedirs(result_dir, mode=0o777, exist_ok=True)

    results = parse_test_log()

    crash_details = parse_crash_details()
    node_name = f"{timestamp}_{grader_name}_crash_details.txt"
    write_log_file(result_dir, node_name, crash_details)

    short_summary = parse_short_summary()
    node_name = f"{timestamp}_{grader_name}_short_crash_summary.txt"
    write_log_file(result_dir, node_name, crash_details)

    node_name = f"{timestamp}_{grader_name}_report.csv"
    out_file_name = os.path.join(result_dir, node_name)
    write_report(results, out_file_name)


if __name__ == "__main__":
    main()
