# PWN从0到1 栈溢出

### 介绍

栈溢出指的是程序向栈中某个变量中写入的字节数超过了这个变量本身所申请的字节数，因而导致与其相邻的栈中的变量的值被改变。这种问题是一种特定的缓冲区溢出漏洞，类似的还有堆溢出，bss 段溢出等溢出方式。栈溢出漏洞轻则可以使程序崩溃，重则可以使攻击者控制程序执行流程。

GCC关闭canary

```
gcc -fno-stack-protector
```

### 栈的传参

- X86

​     函数参数在函数返回地址的上方

- X64

System V AMD64 ABI (Linux、FreeBSD、macOS 等采用) 中前六个整型或指针参数依次保存在 RDI, RSI, RDX,     RCX, R8 和 R9 寄存器中，如果还有更多的参数的话才会保存在栈上。

内存地址不能大于 0x00007FFFFFFFFFFF，6 个字节长度，否则会抛出异常。

### 与栈溢出有关的危险函数

- 输入

- - gets，直接读取一行，忽略'\x00'
  - scanf
  - vscanf

- 输出

- - sprintf

- 字符串

- - strcpy，字符串复制，遇到'\x00'停止
  - strcat，字符串拼接，遇到'\x00'停止
  - bcopy

### 简单模式

#### ret2text

控制程序执行程序本身已有的代码，控制返回一个text段的地址即可。

#### ret2syscall

控制系统调用执行中断。

##### x32

- 系统调用号，即 eax 应该为 0xb
- 第一个参数，即 ebx 应该指向 /bin/sh 的地址，其实执行 sh 的地址也可以。
- 第二个参数，即 ecx 应该为 0
- 第三个参数，即 edx 应该为 0

最后需将地址指向中断号 int 0x80h的地址。

可以使用ROPgadget来寻找。如寻找给寄存器赋值

```
ROPgadget --binary rop  --only 'pop|ret' | grep 'eax
```

寻找int 0x80h中断

```
ROPgadget --binary rop  --only 'int'
```



##### x64

execve("/bin/sh",NULL,NULL)

系统调用号，rax为59

第一个参数，rdi指向/bin/sh

第二个参数，rdx为0

第三个参数，rsi为0

最后指向syscall地址，如何寻找特定寄存器

```
ROPgadget --binary rop  --only 'syscall|ret'
```

#### ret2libc

##### 原理

ret2libc 即控制函数的执行 libc 中的函数，通常是返回至某个函数的 plt 处或者函数的具体位置 (即函数对应的 got 表项的内容)。一般情况下，我们会选择执行 system("/bin/sh")，故而此时我们需要知道 system 函数的地址。

##### 攻击过程

1、获取libc基址

获取libc基址首先泄露已经执行过的函数的地址(got表)，通常是__libc_start_main的绝对地址，然后可以根据LibcSearcher获取libc版本。获取libc版本后，采用绝对地址-偏移地址的方法获取libc的基址。

2、采用基址加偏移地址的方法获取system函数和binsh的绝对地址。

```
#获取libc版本
libc = LibcSearcher('__libc_start_main',libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')

#获取libc中函数偏移地址，如
system_addr = libcbase + libc.dump('system')
```

### 困难模式

#### ret2csu

这个题主要是利用__libc_csu_init函数中的gadget，利用这个函数的原因是x64下前6个参数都是通过寄存器传递的，但是很难找到每一个寄存器对应的gadget。这个函数是用来对libc进行初始化操作的，所以这个函数一定会存在。

这个函数可以控制rdx，rsi和rdi的值（rdi只能控制低32位），还可以控制想要调用的函数的地址。

ret2csu主要是 通过调用write或puts或者printf泄露函数got表中的绝地地址，比对LibcSearcher后获取libc版本，dump libc中的函数地址，相减得libc基址，后面可进行相应的利用。

csu利用的例子如下：

```
def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    payload = 'a' * 0x80 + fakeebp
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    #38对应后面的pop和栈顶抬高
    payload += 'a' * 0x38
    payload += p64(last)
    sh.send(payload)
    sleep(1)
```