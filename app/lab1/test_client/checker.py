import hashlib 

def validate_that_file_is_downloaded(src_file_path, target_file_path):
    assert _hash_file(src_file_path) == _hash_file(target_file_path)

def _hash_file(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as file:
       for data in file:
           hasher.update(read)
    return hasher.digest()