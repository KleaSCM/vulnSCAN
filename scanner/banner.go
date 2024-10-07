package scanner

import (
	"fmt"
	"net"
	"time"
)

func GrabBanner(host string, port int) string {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 1*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Send a request to grab the banner
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	return string(buffer[:n])
}
