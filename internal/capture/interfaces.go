package capture

import (
	"errors"
	"net"
	"net/netip"
)

// LocalAddrs returns the set of IP addresses configured on local interfaces
func LocalAddrs() (map[netip.Addr]bool, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	out := make(map[netip.Addr]bool, 8)
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			out[addr.Unmap()] = true
		}
	}
	return out, nil
}

// defaultInterface picks the first interface that is up, non-loopback, and has
// at least one IP address assigned
func defaultInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		return iface.Name, nil
	}
	return "", errors.New("no suitable network interface found")
}
