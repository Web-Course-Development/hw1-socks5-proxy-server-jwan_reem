package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Step 1: read SOCKS5 greeting header
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		log.Printf("failed to read greeting header: %v", err)
		return
	}

	version := header[0]
	nMethods := int(header[1])

	if version != 0x05 {
		log.Printf("unsupported SOCKS version: %d", version)
		return
	}

	// Step 2: read authentication methods
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		log.Printf("failed to read auth methods: %v", err)
		return
	}

	// Step 3: check if client supports no-auth method 0x00
	supportsNoAuth := false
	for _, method := range methods {
		if method == 0x00 {
			supportsNoAuth = true
			break
		}
	}

	if !supportsNoAuth {
		conn.Write([]byte{0x05, 0xFF})
		log.Printf("client does not support no-auth")
		return
	}

	// Step 4: tell client we selected no-auth
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		log.Printf("failed to write auth response: %v", err)
		return
	}

	log.Printf("SOCKS5 greeting completed successfully")

	// Step 5: read CONNECT request
	targetAddr, err := readConnectRequest(conn)
	if err != nil {
		log.Printf("failed to read CONNECT request: %v", err)
		return
	}

	log.Printf("client requested connection to %s", targetAddr)

	// Step 6: connect to target server
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("failed to connect to target %s: %v", targetAddr, err)
		sendSocksReply(conn, 0x01)
		return
	}
	defer target.Close()

	// Step 7: send success reply to client
	if err := sendSocksReply(conn, 0x00); err != nil {
		log.Printf("failed to send SOCKS reply: %v", err)
		return
	}

	log.Printf("connected successfully to %s", targetAddr)

	// Step 8: relay data in both directions
	go io.Copy(target, conn)
	io.Copy(conn, target)
}

func readConnectRequest(conn net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	version := header[0]
	command := header[1]
	reserved := header[2]
	addressType := header[3]

	if version != 0x05 {
		sendSocksReply(conn, 0x01)
		return "", fmt.Errorf("invalid SOCKS version in request: %d", version)
	}

	if command != 0x01 {
		sendSocksReply(conn, 0x07)
		return "", fmt.Errorf("unsupported command: %d", command)
	}

	if reserved != 0x00 {
		sendSocksReply(conn, 0x01)
		return "", fmt.Errorf("invalid reserved byte: %d", reserved)
	}

	var host string

	switch addressType {
	case 0x01:
		// IPv4 address: 4 bytes
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	case 0x03:
		// Domain name: 1 byte length + domain bytes
		lengthBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lengthBuf); err != nil {
			return "", err
		}

		domainLength := int(lengthBuf[0])
		domain := make([]byte, domainLength)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}

		host = string(domain)

	default:
		sendSocksReply(conn, 0x08)
		return "", fmt.Errorf("unsupported address type: %d", addressType)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}

	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", host, port), nil
}

func sendSocksReply(conn net.Conn, rep byte) error {
	reply := []byte{
		0x05,                   // SOCKS version
		rep,                    // reply code
		0x00,                   // reserved
		0x01,                   // IPv4
		0x00, 0x00, 0x00, 0x00, // bound address = 0.0.0.0
		0x00, 0x00, // bound port = 0
	}

	_, err := conn.Write(reply)
	return err
}
