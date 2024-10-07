package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

func CheckTLS(host string, port int) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		fmt.Printf("Error connecting to %s: %v\n", address, err)
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()

	fmt.Println("SSL/TLS Version:", tlsVersionString(state.Version))
	fmt.Println("Cipher Suite:", tls.CipherSuiteName(state.CipherSuite))
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "Unknown"
	}
}
