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
r = lambda data: p.recv(data)
ru = lambda until, drop=False: p.recvuntil(until, drop=drop)
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

# def encode_shellcode_advanced(shellcode, bad_chars):
#     """
#     Encode shellcode to avoid bad characters using various techniques
#     """
#     encoded = b''
#     for b in shellcode:
#         if bytes([b]) in bad_chars:
#             # Try different encoding techniques
#             if b ^ 0x41 not in bad_chars:  # XOR with 'A'
#                 encoded += asm('''
#                     push 0x41
#                     pop rax
#                     xor al, {}
#                     push rax
#                 '''.format(hex(b ^ 0x41)))
#             elif (b + 1) not in bad_chars:  # Subtract 1
#                 encoded += asm('''
#                     push {}
#                     pop rax
#                     dec al
#                     push rax
#                 '''.format(hex(b + 1)))
#             else:  # Add multiple small numbers
#                 target = b
#                 parts = []
#                 current = 0
#                 while current < target:
#                     part = min(target - current, 0x10)
#                     parts.append(part)
#                     current += part

#                 encoded += asm('''
#                     xor rax, rax
#                     {}
#                     push rax
#                 '''.format('\n'.join(f'add al, {hex(p)}' for p in parts)))
#         else:
#             encoded += bytes([b])
#     return encoded
