import hashlib

hash = hashlib.sha256(input("1980").encode("utf-8")).hexdigest()
print(str(hash))

