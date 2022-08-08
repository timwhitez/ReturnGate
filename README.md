# ReturnGate返程门

## 序

Direct Syscall算是老生常谈的R3层免杀重要技术之一，网上已有非常多相关的开源项目，用的人最多的就是HellsGate以及syswhisper。

把大部分的Direct Syscall项目拆开来，都是由两部分组成的:

1. 绕过EDR监控获取sysid
2. 使用sysid绕过EDR监控调用nt api

本文将介绍一种新的思路用于获取sysid，笔者称其为ReturnGate(返程门)

## 灵感

首先我们进入一个Nt API，

![image](https://user-images.githubusercontent.com/36320909/183412608-1f021d1c-05b8-4d13-a53d-43b5853a6bbd.png)

如上图所示Nt API采用如下的调用方式

```jsx
mov     r10,rcx
mov     eax,xxh
syscall
ret
```

差别就在传入 eax 寄存器的值不同，存储的是系统调用号，即sysid，不同调用号针对syscall 进入内核调用的不同的内核函数。

而对于r3层的edr hook来说，会在api地址的前段加入inline hook，一例：

```jsx
jmp    0xffffffffbffe2f48
int3
int3
int3
...
...
syscall
ret
```

这样在进行API调用的时候就会强制跳转到0xffffffffbffe2f48地址，即为EDR的探针。

在[https://github.com/rad9800/TamperingSyscalls](https://github.com/rad9800/TamperingSyscalls) 项目中， 作者在syscall前加入硬件断点，并且使用空参数调用api后，在断点处的VEH 函数中插入需添加的参数，做到了调用参数不被EDR记录。

我由此项目得到灵感，实现了ReturnGate返程门。

## 实现

由上可知:

1. EDR hook大部分不会影响到syscall;ret指令。
2. 在执行syscall指令时sysid位于eax寄存器中。
3. 使用空参数调用api被记录到的恶意程度较低。
4. 部分EDR会监控自己的钩子是否被脱钩。

由函数调用规约可知:

ret 指令会将eax寄存器的值返回。

那么，就有了一个获取sysid的新手段，使用writeprocessmemory将Nt API的syscall指令修改为nop，再使用空参数调用api, 返回值即为该api的sysid。

此方式由于采用了ret指令获取sysid，故命名ReturnGate(返程门)

实现代码POC如下(Golang):

```go
replace:= []byte{0x90,0x90}
raw:= []byte{0x0f,0x05}

//获取地址
apiName := "NtReadVirtualMemory"
nt := syscall.NewLazyDLL("ntdll").NewProc(apiName).Addr()

//替换
if *(*byte)(unsafe.Pointer(nt+18)) == 0x0f &&
		*(*byte)(unsafe.Pointer(nt+19)) == 0x05 &&
		*(*byte)(unsafe.Pointer(nt+20)) == 0xc3{
		windows.WriteProcessMemory(0xffffffffffffffff,nt+18,(*byte)(unsafe.Pointer(&replace[0])),2,nil)
	}

//空调用获取sysid
sysid,_,_ := syscall.Syscall(nt,0,0,0,0)
fmt.Printf("sysid: %d\n\n",sysid)

//恢复
windows.WriteProcessMemory(0xffffffffffffffff,nt+18,(*byte)(unsafe.Pointer(&raw[0])),2,nil)
```

实现截图：
![image](https://user-images.githubusercontent.com/36320909/183412524-31b349e7-7906-4961-b5fa-671aa8a8b22f.png)
