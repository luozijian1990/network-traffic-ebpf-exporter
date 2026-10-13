package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb Bpf ../../bpf/traffic.c -- -I../../

func LoadObjects() (*BpfObjects, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	objs := BpfObjects{}
	if err := LoadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %v", err)
	}
	return &objs, nil
}
