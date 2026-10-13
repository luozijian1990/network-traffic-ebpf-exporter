package ebpf

import (
	"errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"testing"
)

func TestTCRollbackAndCleanupUseActualIdentity(t *testing.T) {
	for _, failEgress := range []bool{false, true} {
		t.Run(map[bool]string{false: "shutdown", true: "partial failure"}[failEgress], func(t *testing.T) {
			var added, deleted []netlink.Filter
			ops := tcOperations{
				qdiscAdd: func(netlink.Qdisc) error { return unix.EEXIST },
				filterList: func(netlink.Link, uint32) ([]netlink.Filter, error) {
					return []netlink.Filter{&netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{Priority: 100}}}, nil
				},
				filterAdd: func(f netlink.Filter) error {
					if failEgress && f.Attrs().Parent == netlink.HANDLE_MIN_EGRESS {
						return unix.EINVAL
					}
					if f.Attrs().Priority != 99 {
						t.Fatalf("priority=%d", f.Attrs().Priority)
					}
					added = append(added, f)
					return nil
				},
				filterDel: func(f netlink.Filter) error { deleted = append(deleted, f); return nil },
			}
			cleanup, err := attachTC(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "test"}}, 1, 2, ops)
			if failEgress {
				if err == nil {
					t.Fatal("egress failure ignored")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err = cleanup(); err != nil {
					t.Fatal(err)
				}
				if err = cleanup(); err != nil {
					t.Fatal(err)
				}
			}
			if len(added) != len(deleted) {
				t.Fatalf("added %d deleted %d", len(added), len(deleted))
			}
			for i := range added {
				if added[i] != deleted[i] {
					t.Fatal("deleted unowned filter")
				}
			}
		})
	}
}

func TestTCCleanupReportsErrorAndCanRetry(t *testing.T) {
	failure := errors.New("delete failed")
	fail := true
	ops := tcOperations{
		qdiscAdd:   func(netlink.Qdisc) error { return nil },
		filterList: func(netlink.Link, uint32) ([]netlink.Filter, error) { return nil, nil },
		filterAdd:  func(netlink.Filter) error { return nil },
		filterDel: func(netlink.Filter) error {
			if fail {
				return failure
			}
			return nil
		},
	}
	cleanup, err := attachTC(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "test"}}, 1, 2, ops)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(cleanup(), failure) {
		t.Fatal("cleanup error suppressed")
	}
	fail = false
	if err = cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestTCRefusesToOverwriteHighestPriority(t *testing.T) {
	ops := tcOperations{
		qdiscAdd: func(netlink.Qdisc) error { return nil },
		filterList: func(netlink.Link, uint32) ([]netlink.Filter, error) {
			return []netlink.Filter{&netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{Priority: 1}}}, nil
		},
		filterAdd: func(netlink.Filter) error { t.Fatal("must not attach over existing priority"); return nil },
		filterDel: func(netlink.Filter) error { t.Fatal("must not delete unowned filter"); return nil },
	}
	if _, err := attachTC(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2}}, 1, 2, ops); err == nil {
		t.Fatal("unsafe attach accepted")
	}
}
