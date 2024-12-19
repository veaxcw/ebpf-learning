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
	objs := &bpfObjects{}
	err := loadBpfObjects(objs, nil)
	if err != nil {
		log.Fatalf("failed to load eBPF program: %v", err)
	}

	// Attach the eBPF program to the tracepoint for sys_enter_write
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
