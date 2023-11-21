package cidr

import (
	"net"
	"strings"
)

type CIDR struct {
	ip    net.IP
	ipNet *net.IPNet
}

func Parse(s string) (*CIDR, error) {
	i, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return &CIDR{ip: i, ipNet: n}, nil
}

// First returns the first IP address in the CIDR block.
func (c *CIDR) First() net.IP {
	return c.GetNth(0)
}

// GetNth returns the nth IP address in the CIDR block.
func (c *CIDR) GetNth(n int) net.IP {
	ip := make(net.IP, len(c.ip))
	copy(ip, c.ip)
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i] += byte(n + 1)
		if ip[i] != 0 {
			break
		}
	}
	return ip
}

// Mask returns the shorhand mask for the CIDR block.
func (c *CIDR) Mask() string {
	return strings.Split(c.ipNet.String(), "/")[1]
}
