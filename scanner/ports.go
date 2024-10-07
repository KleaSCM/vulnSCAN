package scanner

import (
	"fmt"
	"net"
	"time"
)

func ScanPorts(host string, ports []int) map[int]bool {
	openPorts := make(map[int]bool)

	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			openPorts[port] = true
			conn.Close()
		} else {
			openPorts[port] = false
		}
	}

	return openPorts
}
