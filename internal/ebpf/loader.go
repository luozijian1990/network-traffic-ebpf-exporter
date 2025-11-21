package ebpf

import (
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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

func AttachTC(ifaceName string, objs *BpfObjects) (func(), error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %v", ifaceName, err)
	}
	log.Printf("Found interface %s (index: %d)", ifaceName, link.Attrs().Index)

	// Create clsact qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if !os.IsExist(err) {
			return nil, fmt.Errorf("add clsact qdisc: %v", err)
		}
		log.Printf("clsact qdisc already exists on %s", ifaceName)
	} else {
		log.Printf("Added clsact qdisc to %s", ifaceName)
	}

	// Attach Ingress
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.TcIngress.FD(),
		Name:         "tc_ingress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(ingressFilter); err != nil {
		return nil, fmt.Errorf("add ingress filter: %v", err)
	}
	log.Printf("Attached TC Ingress filter")

	// Attach Egress
	egressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.TcEgress.FD(),
		Name:         "tc_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(egressFilter); err != nil {
		return nil, fmt.Errorf("add egress filter: %v", err)
	}
	log.Printf("Attached TC Egress filter")

	cleanup := func() {
		log.Println("Cleaning up TC filters...")
		netlink.FilterDel(ingressFilter)
		netlink.FilterDel(egressFilter)
		log.Println("TC filters removed")
	}
	return cleanup, nil
}
