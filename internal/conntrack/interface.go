package conntrack

import (
	"fmt"
	"net"
)

func InterfaceIPv4s(name string) (map[uint32]struct{}, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %q: %w", name, err)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("list IPv4 addresses for interface %q: %w", name, err)
	}
	result := make(map[uint32]struct{})
	for _, address := range addresses {
		var ip net.IP
		switch value := address.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		default:
			continue
		}
		if encoded, ok := IPv4ToUint32(ip); ok {
			result[encoded] = struct{}{}
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("interface %q has no IPv4 addresses", name)
	}
	return result, nil
}
