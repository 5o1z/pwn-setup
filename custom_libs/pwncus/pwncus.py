# pwncus.py
from pwn import *

global p
p = None

def set_p(process):
    
    global p
    p = process

# Logging utilities
info = lambda msg: log.info(msg)
slog = lambda name, addr: log.success(': '.join([name, hex(addr)]))

# Send utilities
s = lambda data: p.send(data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
sla = lambda msg, data: p.sendlineafter(msg, data)
sn = lambda num: p.send(str(num).encode())
sna = lambda msg, num: p.sendafter(msg, str(num).encode())
sln = lambda num: p.sendline(str(num).encode())
slna = lambda msg, num: p.sendlineafter(msg, str(num).encode())

# Receive utilities
ru = lambda until: p.recvuntil(until)
rl = lambda: p.recvline()
rlc = lambda data: p.recvline_contains(data)
rb = lambda n_bytes: p.recv(n_bytes)

# New Receive utilities
rnb = lambda n_bytes: p.recvn(n_bytes)

# Interaction
interactive = lambda: p.interactive()

# Additional utilities
encode = lambda e: e if isinstance(e, bytes) else str(e).encode()
hexleak = lambda l: int(l[:-1] if l[-1] == '\n' else l, 16)
fixleak = lambda l: unpack(l.ljust(8, b"\x00"))