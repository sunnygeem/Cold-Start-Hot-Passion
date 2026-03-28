package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate bpf2go -tags linux bpf monitor.c -- -I../headers

// C에서 정의한 struct event와 동일한 구조
type bpfEvent struct {
	Pid         uint32
	StartTimeNs uint64
	DurationNs  uint64
	Comm        [16]byte
}

func main() {
	// 1. 메모리 제한 해제
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 2. 컴파일된 eBPF 객체 로드
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// 3. kprobe & kretprobe 부착
	kp, err := link.Kprobe("sys_execve", objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	krp, err := link.Kretprobe("sys_execve", objs.KretprobeExecve, nil)
	if err != nil {
		log.Fatalf("opening kretprobe: %s", err)
	}
	defer krp.Close()

	// 4. Ring Buffer 리더 생성
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// 시그널 처리 (Ctrl+C 종료)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// fmt.Printf("%-10s %-15s %-20s %-15s\n", "PID", "COMM", "START_TIMESTAMP", "LATENCY(ms)")
	// fmt.Println("---------------------------------------------------------------------------")

	fmt.Printf("%-10s %-15s %-15s %-20s %-10s\n", "PID", "PROCESS", "SYSCALL", "KERNEL_FUNC", "LATENCY(ms)")
	fmt.Println()

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("reading from ringbuf: %v", err)
				continue
			}

			var event bpfEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing ringbuf event: %v", err)
				continue
			}

			// 결과 출력
			comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
			latencyMs := float64(event.DurationNs) / 1000000.0
        		fmt.Printf("%-10d %-15s %-15s %-20s %-10.3f\n",
            		event.Pid, comm, "sys_execve", "kprobe_execve", latencyMs)
		}
	}()

	<-sig
	log.Println("Stopping monitoring...")
}
