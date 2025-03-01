#!/bin/bash
# Why sudo?
# Removing files in the TFTP dir requires sudo.
# Files passed to /srv/tftp need to be owned by tftp.

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
# if [ $# -eq 2 ]
# pytest --tb=auto    # (default) 'long' tracebacks for the first and last
#                      # entry, but 'short' style for the other entries
# pytest --tb=long    # exhaustive, informative traceback formatting
# pytest --tb=short   # shorter traceback format
# pytest --tb=line    # only one line per failure
# pytest --tb=native  # Python standard library formatting
# pytest --tb=no      # no traceback at all
# pytest -svv --tb=line -n 4 -r p -k download app/lab1/test_run_clients.py
# pytest -svv --tb=short -k TestTftpClient app/lab1/test_run_clients.py
# pytest -svv --tb=short -rspx app/lab1/test_incr.py
# pytest -vv --tb=no -k TestTftpClientRx app/lab1/test_run_clients.py
clear
echo -e "\e[33m[LOG] Working... (no output will be shown until the whole process is complete)\e[0m"
pytest -vv --tb=short --show-capture=no app/lab1_client/test_run_clients.py > lab1_client.txt
cat a.txt | python app/lib/console_log_parser.py 1_client
rm lab1_client.txt
pytest -vv --tb=short --show-capture=no app/lab1_server/test_run_servers.py > lab1_server.txt
cat a.txt | python app/lib/console_log_parser.py 1_server
rm lab1_server.txt
echo -e "\e[1m\e[32m[LOG] All done. ─=≡Σ((( つ◕ل͜◕)つ\e[0m"
# pytest -svv --tb=short -k TestTftpClientTx app/lab1/test_run_clients.py
# echo "[LOG] Experiment reached an end..."
# pytest -svv -k download app/lab1/test_run_clients.py
