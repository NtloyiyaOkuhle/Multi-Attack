import hashlib

pass = input("Enter Your Pass: ")
hash = hashlib.sha256(pass.encode("utf-8")).hexdigest()
print(str(hash))

