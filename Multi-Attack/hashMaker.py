import hashlib

hash = hashlib.sha256(input('Enter Your Password: ').encode("utf-8")).hexdigest()
print(str(hash))

