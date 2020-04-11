# This root dir comes from VScode default mounting point.
# https://code.visualstudio.com/docs/remote/containers#_devcontainerjson-reference
ROOT_DIR = "/workspaces/2020-lab1"

CONFIG = {
    # This path comes from the fact that the Dockerfile mounts
    # the directories again.
    "submission_dir_full_path": f"{ROOT_DIR}/lab1/submissions/2020/",
    # File name without any paths relative/absolute.
    "test_file_name": "file-template.txt",
    # Path where the file templates exist. (test files)
    "static_files_path": f"{ROOT_DIR}/lab1/assets/",
}
