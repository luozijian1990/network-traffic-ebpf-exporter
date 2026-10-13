package ebpf

import (
	"fmt"
	"os"
	"sync"
	"testing"
)

// Runs the real compiled TC programs in the Linux kernel, without attaching
// them to an interface. Enable explicitly on a host with BPF privileges.
func TestConcurrentFirstPacketAndClassifierContinuation(t *testing.T) {
	if os.Getenv("BPF_INTEGRATION") != "1" {
		t.Skip("set BPF_INTEGRATION=1 on a privileged Linux host")
	}
	objs, err := LoadObjects()
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	packet := make([]byte, 64)
	packet[12] = 8
	packet[14] = 0x45
	packet[16] = 0
	packet[17] = 50
	copy(packet[26:30], []byte{198, 18, 0, 1})
	copy(packet[30:34], []byte{198, 18, 0, 2})
	const workers = 32
	for trial := 0; trial < 100; trial++ {
		packet[29] = byte(trial + 1)
		key := BpfKeyT{SrcIp: uint32(198) | uint32(18)<<8 | uint32(trial+1)<<24, DstIp: uint32(198) | uint32(18)<<8 | uint32(2)<<24}
		start := make(chan struct{})
		failures := make(chan error, workers)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				ret, _, err := objs.TcIngress.Test(packet)
				if err != nil {
					failures <- err
				} else if ret != ^uint32(0) {
					failures <- fmt.Errorf("return %d, want TC_ACT_UNSPEC", ret)
				}
			}()
		}
		close(start)
		wg.Wait()
		close(failures)
		for err := range failures {
			t.Fatal(err)
		}
		var value BpfValueT
		if err = objs.TrafficStats.Lookup(&key, &value); err != nil {
			t.Fatal(err)
		}
		if value.Packets != workers || value.Bytes != workers*uint64(len(packet)) {
			t.Fatalf("trial %d lost packets: %+v", trial, value)
		}
	}
	ret, _, err := objs.TcEgress.Test(packet)
	if err != nil || ret != ^uint32(0) {
		t.Fatalf("egress return=%d error=%v", ret, err)
	}
	// Non-IPv4 packets must also continue to subsequent classifiers.
	packet[12] = 0x86
	packet[13] = 0xdd
	ret, _, err = objs.TcIngress.Test(packet)
	if err != nil || ret != ^uint32(0) {
		t.Fatalf("non-IPv4 return=%d error=%v", ret, err)
	}
}
