from app.lib.app_config import YEAR, ROOT_DIR

# This root dir comes from VScode default mounting point.
# https://code.visualstudio.com/docs/remote/containers#_devcontainerjson-reference
LAB_ROOT_DIR = f"{ROOT_DIR}/lab1"
TEST_TIMEOUT = 0.5
CONFIG = {
    # This path comes from the fact that the Dockerfile mounts
    # the directories again.
    "client_submission_dir_full_path": f"{LAB_ROOT_DIR}/submissions/{YEAR}/client",
    "server_submission_dir_full_path": f"{LAB_ROOT_DIR}/submissions/{YEAR}/server",
    # File name without any paths relative/absolute.
    "test_file_name": "file-template.txt",
    # Path where the file templates exist. (test files)
    "static_files_path": f"{LAB_ROOT_DIR}/assets",
    # Random files for upload/download will go here
    "scratch_disk": f"{LAB_ROOT_DIR}/scratch_disk"
}
