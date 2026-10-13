package main

import (
	"net"
	"strings"
	"testing"
)

func TestOccupiedHTTPAddressFailsBeforeBPFOrTC(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	savedAddr, savedIface := *addr, *ifaceName
	defer func() { *addr = savedAddr; *ifaceName = savedIface }()
	*addr = listener.Addr().String()
	*ifaceName = "does-not-exist"
	if err = run(); err == nil || !strings.Contains(err.Error(), "listen on") {
		t.Fatalf("got %v", err)
	}
}
