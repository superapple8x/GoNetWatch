package discovery

import (
	"net"
)

// Host represents a discovered network device
type Host struct {
	IP   net.IP
	MAC  net.HardwareAddr
	Name string // Optional: Hostname if resolvable
}
