package utils

import (
	"net"
)

func IsPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	privateIPBlocks := []*net.IPNet{
		ParseCIDR("10.0.0.0/8"),
		ParseCIDR("172.16.0.0/12"),
		ParseCIDR("192.168.0.0/16"),
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func ParseCIDR(s string) *net.IPNet {
	_, block, _ := net.ParseCIDR(s)
	return block
}

func IntToIP(ip uint32) string {
	result := make(net.IP, 4)
	result[0] = byte(ip)
	result[1] = byte(ip >> 8)
	result[2] = byte(ip >> 16)
	result[3] = byte(ip >> 24)
	return result.String()
}
