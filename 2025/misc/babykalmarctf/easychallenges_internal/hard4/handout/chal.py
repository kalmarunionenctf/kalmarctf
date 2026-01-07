from hashlib import md5

with open("flag.txt", "rb") as f:
    flag = f.read()

# open-ECSC vibes
hsh = md5(flag).hexdigest()


with open("output.txt", "w") as f:
    f.write(hsh)