import hashlib

hash = hashlib.sha256(('1980').encode("utf-8")).hexdigest()
print(str(hash))

