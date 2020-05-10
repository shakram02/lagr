import csv
import os
import numpy as np
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


def parse_test_log(file_path, accumulator: dict):
    # HACK: I'll just pipe pytest's to this process's std
    # and skip parsing whenever non matching output are available,
    # because blah!
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

    crash_log = open(file_path, "w")
    crash_details = parse_crash_details()
    crash_log.writelines(crash_details)


def parse_crash_details():
    crash_details = []
    for line in sys.stdin:
        if "= short test summary info =" in line:
            break
        line = [letter for letter in line if letter in string.printable]
        crash_details.append("".join(line))

    return crash_details


def write_results_file(accumulator: dict, root_dir, prefix):
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
    out_file_name = os.path.join(root_dir, prefix + "_results.csv")
    with open(out_file_name, "w") as f:
        writer = csv.writer(f)
        for row in csv_array:
            writer.writerows(row)

    print("AVG", mean)
    print("Output file:", out_file_name)


def main():
    root_dir = f"{ROOT_DIR}/lab1/submissions/{YEAR}"
    results = {}

    fname = "lost_client"
    p = os.path.join(root_dir, fname+"_crash_logs.txt")
    # TODO: clean this up.
    print("Emitting:", f"\u001B[1m\u001B[34m{p}\u001B[0m")
    parse_test_log(p, results)
    # parse_test_log(log_dir + "client_tx_logs.txt", results)
    write_results_file(results, root_dir, fname)
    # pprint(results)


if __name__ == "__main__":
    main()
