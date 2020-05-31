from app_config import YEAR, ROOT_DIR
import csv
import os
import numpy as np
import time
import json
import sys
from pprint import pprint
import re
import string
test_submission_id_result_regex = re.compile(r"(test_\w+)\[(.*?)\]\s(\w+)")
st_tests = dict()

# Final result multiplier for cheaters & late.
MULTIPLIER = 1


class CaseConfig(object):
    def __init__(self, case_config_map):
        self.out_name = case_config_map["out_name"]
        self.weight = case_config_map["weight"]


class TestResult(object):
    def __init__(self, name, student_id, weight, result):
        self.name = name
        self.student_id = student_id
        self.weight = weight
        if result == "PASSED":
            self.passed = True
            self.result = "✔"
        elif result == "FAILED":
            self.passed = False
            self.result = "✘"
        else:
            raise RuntimeError(f"Illegal result [{result}]")

    def __repr__(self):
        return f"{self.name}:{self.student_id}:{self.result}"

    def __str__(self):
        return self.__repr__()


def parse_test_log(result_config):
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
        try:
            human_friendly_name = result_config[case_name]
        except KeyError:
            print(
                f"[ERROR] Case: {case_name} isn't found in result_config.json file.")
            exit(-1)

        case_config = CaseConfig(human_friendly_name)
        test_result = TestResult(case_config.out_name,
                                 st_ids, case_config.weight, result)

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
    """
    Converts test results to human readable
    CSV file.

    When a multiplier is used, it's applied
    to the total.
    """
    def get_percentage(passed, total):
        return round((passed/total), 2)

    csv_array = []
    passed_statistics = []
    report_summary = []
    for k in accumulator.keys():
        st_ids = k
        student_case_info = [["ID", k]]
        passed = 0
        total = 0
        for r in accumulator[st_ids]:
            total += r.weight
            case_brief = f"{r.name} [{r.weight}]"
            student_case_info.append((case_brief, r.result))
            if r.passed:
                passed += r.weight

        passed_statistics.append(passed)
        csv_array.append(student_case_info)
        inline_summary = [["OK", passed]]

        # Apply scaling. (for late & cheaters)
        if MULTIPLIER == 1:
            inline_summary.append(["TOTAL", total])
        else:
            inline_summary.append(
                [f"TOTAL (x {MULTIPLIER})", total * MULTIPLIER])

        csv_array.append(inline_summary)
        csv_array.append([[]])

        percentage = get_percentage(passed, total)
        report_summary.append((st_ids, percentage))

    arr = np.asarray(passed_statistics)
    mean = round(arr.mean(), 4)
    max_val = max(passed_statistics)
    mean_max = round(mean/max_val, 2)
    min_val = min(passed_statistics)
    stdev = round(arr.std(), 4)

    csv_array.append([["MEAN", mean], ["MEAN/MAX", mean_max]])
    print("\n".join([str(x) for x in passed_statistics]))

    with open(file_path, "w") as f:
        writer = csv.writer(f)
        for row in csv_array:
            writer.writerows(row)

    print("MEAN", mean, "MAX", max_val, "MEAN/MAX", mean_max, "STDev", stdev)
    return report_summary


def expand_ids_in_summary(report_summary):
    """
    Converts submission IDs on the form ID1_ID2
    to an array [ID1, ID2].

    If the submission has only 1 ID this
    function won't have any effect.
    """
    result = {}
    for (concat_st_ids, percentage) in report_summary:
        st_ids = concat_st_ids.split("_")
        for st_id in st_ids:
            result[st_id] = percentage

    result = sorted(result.items(), key=lambda item: item[0])
    result = [(k, v) for k, v in result]
    return result


def write_grade_sheet(report_summary):
    summary = expand_ids_in_summary(report_summary)
    # Output as csv
    return [f"{st_id},{percentage}\n" for (st_id, percentage) in summary]


def write_log_file(result_dir, node_name, log_lines):
    node_path = os.path.join(result_dir, node_name)

    with open(node_path, "w") as log_file:
        log_file.writelines(log_lines)

    print(f"[LOG] File written: {node_name}")


def get_result_config(lab_number):
    result_config_dir = f"{ROOT_DIR}/lab{lab_number}/result_config.json"
    with open(result_config_dir) as fp:
        return json.loads(fp.read())

# It's advisable to leave pytest output in a file.
# pytest > file && cat file | python console_log_parser


def main():
    global MULTIPLIER
    lab_number = sys.argv[1]

    if len(sys.argv) == 3:
        try:
            MULTIPLIER = float(sys.argv[2])
        except Exception:
            print("[ERROR] Expected a float number (multiplier) as a second argument.")
            exit(-1)

    result_config = get_result_config(lab_number)
    grader_name = result_config["name"]
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

    results = parse_test_log(result_config)

    crash_details = parse_crash_details()
    node_name = f"{timestamp}_{grader_name}_crash_details.txt"
    write_log_file(result_dir, node_name, crash_details)

    short_summary = parse_short_summary()
    node_name = f"{timestamp}_{grader_name}_short_crash_summary.txt"
    write_log_file(result_dir, node_name, short_summary)

    node_name = f"{timestamp}_{grader_name}_report.csv"
    out_file_name = os.path.join(result_dir, node_name)
    report_summary = write_report(results, out_file_name)

    grade_summary = write_grade_sheet(report_summary)
    node_name = f"{timestamp}_{grader_name}_grade_summary.csv"
    write_log_file(result_dir, node_name, grade_summary)


if __name__ == "__main__":
    main()
