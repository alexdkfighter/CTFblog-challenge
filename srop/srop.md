| 寄存器和指令 | 存储数据        |
|:------:|:-----------:|
| rax    | read函数系统调用号 |
| rdi    | 0           |
| rsi    | stack_addr  |
| rdx    | 0x400       |
| rsp    | stack_addr  |
| rip    | syscall_ret |



●首先是rax寄存器中一定是存放read函数的系统调用号啦，因为原汇编代码使用的是syscall，这个不多说了  
●rdi寄存器作为read函数的一参，0代表标准输入  
●rsi寄存器作为read函数的二参，里面存放的是前面通过write函数打印出来的新栈顶的地址，也就是说将接收到的信息写到我们前面通过write函数打印的新栈顶的位置  
●rdx作为read函数的三参写0x400个字节  
●rsp寄存器需要和rsi保持一致，在写的时候写在rsp指向的位置  
●rip寄存器指向syscall_ret，确保在read函数寄存器部署成功之后可以直接调用read函数
