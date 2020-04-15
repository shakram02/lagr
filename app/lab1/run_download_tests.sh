# Cheatsheet
# https://gist.github.com/kwmiebach/3fd49612ef7a52b5ce3a
# -n number of workers
# -k test case pattern
# 
# -r Flag to print results:
# f - failed
# E - error
# s - skipped
# x - xfailed
# X - xpassed
# p - passed
# P - passed with output

# pytest --tb=auto    # (default) 'long' tracebacks for the first and last
#                      # entry, but 'short' style for the other entries
# pytest --tb=long    # exhaustive, informative traceback formatting
# pytest --tb=short   # shorter traceback format
# pytest --tb=line    # only one line per failure
# pytest --tb=native  # Python standard library formatting
# pytest --tb=no      # no traceback at all
# pytest -svv --tb=line -n 4 -r p -k download app/lab1/test_run_clients.py
pytest -vv --tb=short -k exp_sending_rrq app/lab1/test_run_clients.py
echo "[LOG] Experiment reached an end..."
# pytest -svv -k download app/lab1/test_run_clients.py
