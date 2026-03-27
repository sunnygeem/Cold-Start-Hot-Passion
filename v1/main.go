package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -cc clang bpf trace_exec.bpf.c -- -O2 -g

type event struct {
	TsNs uint64
	Pid  uint32
	Comm [16]byte
}

func main() {
	// eBPF 리소스를 위해 memlock 제한 해제
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// bpf2go로 생성된 오브젝트 로드
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// sys_execve 진입점에 kprobe attach
	kp, err := link.Kprobe("sys_execve", objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %v", err)
	}
	defer kp.Close()

	// ring buffer reader 생성
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf: %v", err)
	}
	defer rd.Close()

	log.Println("Waiting for execve events... Ctrl+C to stop")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		_ = rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				log.Println("exiting...")
				return
			}
			log.Printf("reading ringbuf: %v", err)
			continue
		}

		var e event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}

		comm := strings.TrimRight(string(e.Comm[:]), "\x00")
		fmt.Printf("ts_ns=%d pid=%d comm=%s\n", e.TsNs, e.Pid, comm)
	}
}

