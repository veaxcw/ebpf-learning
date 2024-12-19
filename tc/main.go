package main

import (
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf tc.bpf.c

type dataT struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
	Total uint32
	TTL   uint32
}

func main() {
	// 提高资源限制，允许加载 eBPF 程序
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock limit: %v", err)
	}
	obj := &bpfObjects{}
	err := loadBpfObjects(obj, nil)
	if err != nil {
		log.Fatalf("failed to load eBPF program: %v", err)
	}
	//options := link.TCXOptions{
	//	Interface: eth0.Index, // 挂载网卡
	//	Program:   obj.TcIngress,
	//	Attach:    ebpf.AttachCGroupInetIngress, // 挂载点
	//}
	// 需要kernel 6.6 以上版本
	//tcx, err := link.AttachTCX(options)
	//if err != nil {
	//	log.Fatalf("failed to attach eBPF program: %v", err)
	//}
	//defer tcx.Close()

	err = attachProgom(err, obj)
	reader, err := perf.NewReader(obj.bpfMaps.Events, 4096)
	if err != nil {
		log.Fatalf("failed to new perf reader: %v", err)
	}

	// 捕获 Ctrl+C 信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				log.Printf("Failed to read from perf buffer: %v", err)
				continue
			}

			if record.LostSamples > 0 {
				log.Printf("Lost %d samples", record.LostSamples)
				continue
			}
			log.Printf("raw data:%v", record.RawSample)

			event := &dataT{
				Saddr: binary.BigEndian.Uint32(record.RawSample[0:4]),
				Daddr: binary.BigEndian.Uint32(record.RawSample[4:8]),
				Sport: binary.LittleEndian.Uint16(record.RawSample[8:10]),
				Dport: binary.LittleEndian.Uint16(record.RawSample[10:12]),
				Total: binary.BigEndian.Uint32(record.RawSample[12:16]),
				TTL:   binary.BigEndian.Uint32(record.RawSample[16:20]),
			}

			// 打印提取的 IP 和 TCP 头信息
			srcIP := net.IPv4(byte(event.Saddr>>24), byte(event.Saddr>>16), byte(event.Saddr>>8), byte(event.Saddr))
			dstIP := net.IPv4(byte(event.Daddr>>24), byte(event.Daddr>>16), byte(event.Daddr>>8), byte(event.Daddr))
			fmt.Printf("Source IP: %s, Dest IP: %s, Source Port: %d, Dest Port: %d\n",
				srcIP.String(), dstIP.String(), event.Sport, event.Dport)
			time.Sleep(1 * time.Second)
		}
	}()

	// 等待信号
	<-sig
	fmt.Println("Exiting program...")
}

func attachProgom(err error, obj *bpfObjects) error {
	// 找到要挂载 eBPF 程序的网络接口
	iface, err := netlink.LinkByName("eth0")
	if err != nil {
		log.Fatalf("failed to find eth0: %s", err)
	}

	// 创建 clsact qdisc
	handle, err := netlink.NewHandle()
	if err != nil {
		log.Fatalf("cannot to create a new netlink handle: %s", err)
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    netlink.HANDLE_INGRESS,
		},
		QdiscType: "clsact",
	}

	err = handle.QdiscAdd(qdisc)
	if err != nil && err != os.ErrExist {
		log.Fatalf("failed to create : %s", err)
	}

	// 挂载 eBPF 程序到 ingress
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Handle:    netlink.MakeHandle(0x1, 0),
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           obj.bpfPrograms.TcIngress.FD(),
		Name:         "tc_ingress",
		DirectAction: true,
	}

	err = netlink.FilterAdd(ingressFilter)
	if err != nil {
		log.Fatalf("挂载 eBPF 程序到 ingress 失败: %s", err)
	}
	return err
}
