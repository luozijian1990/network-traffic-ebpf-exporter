package ebpf

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type tcOperations struct {
	qdiscAdd   func(netlink.Qdisc) error
	filterList func(netlink.Link, uint32) ([]netlink.Filter, error)
	filterAdd  func(netlink.Filter) error
	filterDel  func(netlink.Filter) error
}

func AttachTC(ifaceName string, objs *BpfObjects) (func() error, error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", ifaceName, err)
	}
	return attachTC(link, objs.TcIngress.FD(), objs.TcEgress.FD(), tcOperations{
		qdiscAdd: netlink.QdiscAdd, filterList: netlink.FilterList,
		filterAdd: netlink.FilterAdd, filterDel: netlink.FilterDel,
	})
}

func attachTC(link netlink.Link, ingressFD, egressFD int, ops tcOperations) (func() error, error) {
	qdisc := &netlink.GenericQdisc{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT,
	}, QdiscType: "clsact"}
	if err := ops.qdiscAdd(qdisc); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("add clsact qdisc: %w", err)
	}
	// clsact is shared; cleanup removes only filters successfully added here.
	var attached []netlink.Filter
	cleanup := func() error {
		var failures []error
		var remaining []netlink.Filter
		for _, filter := range attached {
			if err := ops.filterDel(filter); err != nil && !errors.Is(err, unix.ENOENT) {
				failures = append(failures, fmt.Errorf("delete %s priority %d: %w", filter.Type(), filter.Attrs().Priority, err))
				remaining = append(remaining, filter)
			}
		}
		attached = remaining
		return errors.Join(failures...)
	}
	for _, spec := range []struct {
		parent uint32
		fd     int
		name   string
	}{
		{netlink.HANDLE_MIN_INGRESS, ingressFD, "tc_ingress"},
		{netlink.HANDLE_MIN_EGRESS, egressFD, "tc_egress"},
	} {
		filters, err := ops.filterList(link, spec.parent)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("list %s filters: %w", spec.name, err), cleanup())
		}
		// Observe before existing classifiers, but return UNSPEC so they still run.
		// Explicit priority makes the identity usable for rollback and cleanup.
		priority := uint16(49152)
		for _, filter := range filters {
			if filter.Attrs().Priority <= priority {
				priority = filter.Attrs().Priority
			}
		}
		if len(filters) > 0 {
			if priority <= 1 {
				return nil, errors.Join(fmt.Errorf("no priority available before existing %s filters", spec.name), cleanup())
			}
			priority--
		}
		filter := &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index, Parent: spec.parent, Handle: netlink.MakeHandle(0, 1),
			Priority: priority, Protocol: unix.ETH_P_ALL,
		}, Fd: spec.fd, Name: spec.name, DirectAction: true}
		if err := ops.filterAdd(filter); err != nil {
			return nil, errors.Join(fmt.Errorf("add %s filter: %w", spec.name, err), cleanup())
		}
		attached = append(attached, filter)
		log.Printf("attached %s on %s priority %d", spec.name, link.Attrs().Name, priority)
	}
	return cleanup, nil
}
