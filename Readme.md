## 了解eBPF



### Map

### BPF_MAP_TYPE_HASH

`BPF_MAP_TYPE_HASH`一般就是用于内核态和用户态之间传输数据. 这个目前是最为常见



#### BPF_MAP_TYPE_PERF_EVENT_ARRAY

`BPF_MAP_TYPE_PERF_EVENT_ARRAY`是eBPF（Extended Berkeley Packet Filter）中的一种特殊类型的映射（map）。它用于在eBPF程序和用户空间之间传递性能事件（perf events）。

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");
```



### 挂载点

#### TC

TC有4大组件：

- **Queuing disciplines**，简称为**qdisc**，直译是「队列规则」，它的本质是一个带有算法的队列，默认的算法是**FIFO**，形成了一个最简单的流量调度器。
- **Class**，直译是「种类」，它的本质是为上面的qdisc进行分类。因为现实情况下会有很多qdisc存在，每种qdisc有它特殊的职责，根据职责的不同，可以对qdisc进行分类。
- **Filters**，直译是「过滤器」，它是用来过滤传入的网络包，使它们进入到对应class的qdisc中去。
- **Policers**，直译是「规则器」，它其实是filter的跟班，通常会紧跟着filter出现，定义命中filter后网络包的后继操作，如丢弃、延迟或限速。



### 编译器

Clang/LLVM 为它提供了一个**编译后端**， 能从 C 源码直接生成 eBPF 字节码（bytecode）。



## 环境准备

```shell
# 操作系统选择的ubuntu 22.05 内核版本为5.15
root@ebpf:~# uname -a
Linux ebpf 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux

# 编译器安装
apt install llvm clang

# 安装依赖
apt install libbpf-dev

# golang 安装，版本为1.23.1，包直接从官网下载
 rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.1.linux-amd64.tar.gz
 export PATH=$PATH:/usr/local/go/bin
 
 #SDK github.com/cilium/ebpf
 
 # 解决asm/xxx.h 找不到
ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
 
```

### 工具

BPFTOOL 是linux内核自带的用于对eBPF程序和eBPF map进行检查与操作的工具软件

#### 安装

```shell
# 安装bpftool
apt install  linux-tools-5.15.0-113-generic

```

#### 使用

```shell
# 生成头文件,内核用的结构体比如sk_buff等都可以在里面依赖到
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```



#### 常用命令

```shell
# 查看eth0 上挂在的 ingress ebpf 程序
tc filter show dev eth0 ingress
# 删除优先级为1的程序
tc filter del dev eth0 ingress protocol all pref 49152
# 删除qdisc
tc qdisc del dev eth0 clsact

```



## 代码示例

ebpf 代码分为部分，内核态程序，和用户态程序，内核态用c代码编写，用户态用go，通过cilium/ebpf 提供的ebpfgo， 将c代码编译成字节码，用户态用go 编译

#### 代码结构

```shell
root@ebpf:/opt/ebpf-learning# tree
├── go.mod
├── go.sum
└── helloword
    ├── helloword.c -- 内核态代码
    └── main.go -- 用户态代码
    
```

#### *编译*

```
root@ebpf:/opt/ebpf-learning# go generate && go build
.
├── go.mod
├── go.sum
└── helloword
    ├── bpf_bpfeb.go -- 生成的go代码
    ├── bpf_bpfeb.o --大端字节码文件
    ├── bpf_bpfel.go
    ├── bpf_bpfel.o --小段字节码文件
    ├── helloword.c
    └── main.go
```

一下程序参考https://github.com/eunomia-bpf/bpf-developer-tutorial提供的示例，全部用go 重写

#### 监控sys_enter_write系统调用

内核态代码部分，这是简单的记录进程ID

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef unsigned int u32;
typedef int pid_t;

char __license[] SEC("license") = "Dual MIT/GPL";

# 监控sys_enter_writ 系统调用
SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{	
    pid_t pid = bpf_get_current_pid_tgid() >> 32; // 高32位为进程ID，低32位为线程ID，这里取进程ID
    bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid); // bpf_printk打印的日记输出到/sys/kernel/debug/tracing/trace_pipe
    return 0;
}


```

用户态代码部分

```go
package main

import (
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"syscall"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf helloword.c -- -I../headers

func main() {
	// 提高资源限制，允许加载 eBPF 程序
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock limit: %v", err)
	}
  // 加载go generate 生成的bpf程序
	objs := &bpfObjects{}
	err := loadBpfObjects(objs, nil)
	if err != nil {
		log.Fatalf("failed to load eBPF program: %v", err)
	}
	// 将eBPF程序挂在到tracepointe
	tp, err := link.Tracepoint("syscalls", "sys_enter_write", objs.HandleTp, nil)
	if err != nil {
		log.Fatalf("failed to attach to tracepoint: %v", err)
	}
	defer tp.Close()

	// 捕获退出信号以清理资源
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("Exiting program...")
}

```

执行结果

    root@ebpf:~# cat /sys/kernel/debug/tracing/trace_pipe
    cat-17806   [001] ....1  8620.865775: bpf_trace_printk: BPF triggered sys_enter_write from PID 17806.

#### tc_ingress 监控tcp报文

代码目录：ebpf-learning/tc

技术点：

1，ebpf代码的挂载点为tc

2，使用netlink将ebpf代码挂在到eth0的tc上面

3，使用BPF_MAP_TYPE_PERF_EVENT_ARRAY类型的map，向用户态传递事件，事件内容为IP四元组



执行结果

```
root@ebpf:~# ./tc
2024/09/22 16:24:17 raw data:[113 89 5 199 192 168 0 37 37 219 22 0 0 52 0 0 49 0 0 0]
Source IP: 113.89.5.199, Dest IP: 192.168.0.37, Source Port: 56101, Dest Port: 22
2024/09/22 16:24:18 raw data:[113 89 5 199 192 168 0 37 37 219 22 0 0 52 0 0 49 0 0 0]
Source IP: 113.89.5.199, Dest IP: 192.168.0.37, Source Port: 56101, Dest Port: 22
2024/09/22 16:24:19 raw data:[100 125 4 80 192 168 0 37 196 39 156 168 0 52 0 0 59 0 0 0]
Source IP: 100.125.4.80, Dest IP: 192.168.0.37, Source Port: 10180, Dest Port: 43164
2024/09/22 16:24:20 raw data:[100 125 4 80 192 168 0 37 196 39 156 168 0 40 0 0 59 0 0 0]
Source IP: 100.125.4.80, Dest IP: 192.168.0.37, Source Port: 10180, Dest Port: 43164
2024/09/22 16:24:21 raw data:[100 125 4 80 192 168 0 37 196 39 156 168 5 38 0 0 59 0 0 0]
Source IP: 100.125.4.80, Dest IP: 192.168.0.37, Source Port: 10180, Dest Port: 43164
2024/09/22 16:24:22 raw data:[100 125 4 80 192 168 0 37 196 39 156 168 1 74 0 0 59 0 0 0]
Source IP: 100.125.4.80, Dest IP: 192.168.0.37, Source Port: 10180, Dest Port: 43164
```





## 问题踩坑记录

### asm/types.h 找不到

```shell
# 
root@ebpf:/opt/ebpf-learning/helloword# go generate
In file included from /opt/ebpf-learning/helloword/helloword.c:2:
In file included from /usr/include/linux/bpf.h:11:
/usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found
#include <asm/types.h>
         ^~~~~~~~~~~~~
1 error generated.
Error: compile: exit status 1


ln -sf /usr/include/asm-generic/ /usr/include/asm
```

### 大端，小端，网络字节顺序

大端：高字节存放在低地址，低字节存放在高地址（大端从左往右，很符合人的思维）

小端：低字节存放在低地址，高字节存放在高地址（低放低，大端的逆序）

```
比如字节数组中前32位，为IP地址113.89.5.19
大端： [113 89 5 199]
小端：

```



## 参考

[ LLVM eBPF 汇编编程]: https://arthurchiao.art/blog/ebpf-assembly-with-llvm-zh/

https://github.com/eunomia-bpf/bpf-developer-tutorial

