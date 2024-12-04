package main

import (
	"crypto/rand"
	"encoding/binary"
	"net"
)

const (
	ipv4HeaderSize  = 20
	udpHeaderSize   = 8
	minFragmentSize = 28   // IP header (20 bytes) + minimum payload (8 bytes)
	defaultFragSize = 1480 // Default fragment size (fits in most MTUs)
)

func fragmentData(data []byte, maxSize int) [][]byte {
	var fragments [][]byte
	for i := 0; i < len(data); i += maxSize {
		end := i + maxSize
		if end > len(data) {
			end = len(data)
		}
		fragments = append(fragments, data[i:end])
	}
	return fragments
}

func generateValidRandomIPv4() (string, error) {
	for {
		ip := make(net.IP, 4)
		_, err := rand.Read(ip)
		if err != nil {
			return "", err
		}

		if isValidPublicIP(ip) {
			return ip.String(), nil
		}
	}
}

func isValidPublicIP(ip net.IP) bool {
	// Check if it's an IPv4 address
	if ip.To4() == nil {
		return false
	}

	// Filter private IP ranges
	if ip[0] == 10 || // 10.0.0.0/8
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || // 172.16.0.0/12
		(ip[0] == 192 && ip[1] == 168) || // 192.168.0.0/16
		(ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127) { // 100.64.0.0/10 (CGNAT)
		return false
	}

	// Filter loopback addresses
	if ip[0] == 127 { // 127.0.0.0/8
		return false
	}

	// Filter link-local addresses
	if ip[0] == 169 && ip[1] == 254 { // 169.254.0.0/16
		return false
	}

	// Filter reserved multicast addresses
	if ip[0] >= 224 && ip[0] <= 239 { // 224.0.0.0/4 to 239.0.0.0/8
		return false
	}

	// Filter reserved and broadcast addresses
	if ip[0] >= 240 || // 240.0.0.0/4
		(ip[0] == 0) || // 0.0.0.0/8
		(ip[0] == 192 && ip[1] == 0 && ip[2] == 0) || // 192.0.0.0/24
		(ip[0] == 192 && ip[1] == 0 && ip[2] == 2) || // 192.0.2.0/24
		(ip[0] == 192 && ip[1] == 88 && ip[2] == 99) || // 192.88.99.0/24
		(ip[0] == 198 && ip[1] >= 18 && ip[1] <= 19) || // 198.18.0.0/15
		(ip[0] == 198 && ip[1] == 51 && ip[2] == 100) || // 198.51.100.0/24
		(ip[0] == 203 && ip[1] == 0 && ip[2] == 113) { // 203.0.113.0/24
		return false
	}

	return true
}

func BuildUDPFragment(conn net.Conn, data []byte, fragmentOffset, totalFragments uint16) []byte {
	// Construct IP header
	ipHeader := make([]byte, ipv4HeaderSize)
	ipHeader[0] = 0x45 // Version(4) + Header Length(5)
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(ipv4HeaderSize+len(data)))

	// Set fragmentation flags and offset
	flags := uint16(0x2000) // "More fragments" flag
	if fragmentOffset == totalFragments-1 {
		flags = 0 // Last fragment
	}
	fragOffset := (fragmentOffset * uint16(len(data))) / 8
	binary.BigEndian.PutUint16(ipHeader[6:8], flags|fragOffset)

	ipHeader[8] = 64 // TTL
	ipHeader[9] = 17 // UDP

	// Set source and destination IP
	sourceIp, _, _ := net.SplitHostPort(conn.LocalAddr().String())
	destIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	copy(ipHeader[12:16], net.ParseIP(sourceIp).To4())
	copy(ipHeader[16:20], net.ParseIP(destIP).To4())

	// Calculate IP header checksum
	ipHeader[10] = 0
	ipHeader[11] = 0
	checksum := calculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum)

	// Combine packet
	packet := append(ipHeader, data...)
	return packet
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return uint16(^sum)
}
