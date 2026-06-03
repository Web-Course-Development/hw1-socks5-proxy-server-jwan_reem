package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
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

	method, err := negotiateAuth(conn)
	if err != nil {
		log.Printf("auth negotiation error: %v", err)
		return
	}

	if method == 0x02 {
		if err := authenticateUserPass(conn); err != nil {
			log.Printf("authentication failed: %v", err)
			return
		}
	}

	targetAddr, err := readConnectRequest(conn)
	if err != nil {
		log.Printf("failed to read CONNECT request: %v", err)
		return
	}

	log.Printf("client requested connection to %s", targetAddr)

	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("failed to connect to target %s: %v", targetAddr, err)
		sendSocksReply(conn, 0x01)
		return
	}
	defer target.Close()

	if err := sendSocksReply(conn, 0x00); err != nil {
		log.Printf("failed to send SOCKS reply: %v", err)
		return
	}

	log.Printf("connected successfully to %s", targetAddr)

	relay(conn, target)
}

func negotiateAuth(conn net.Conn) (byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}

	if header[0] != 0x05 {
		return 0, fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, err
	}

	authRequired := os.Getenv("PROXY_USER") != ""

	var selected byte = 0xFF

	for _, method := range methods {
		if authRequired && method == 0x02 {
			selected = 0x02
			break
		}

		if !authRequired && method == 0x00 {
			selected = 0x00
			break
		}
	}

	if _, err := conn.Write([]byte{0x05, selected}); err != nil {
		return 0, err
	}

	if selected == 0xFF {
		return 0, fmt.Errorf("no acceptable authentication method")
	}

	return selected, nil
}

func authenticateUserPass(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != 0x01 {
		conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid username/password auth version: %d", header[0])
	}

	usernameLen := int(header[1])
	username := make([]byte, usernameLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		return err
	}

	passwordLen := int(passLenBuf[0])
	password := make([]byte, passwordLen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if string(username) == expectedUser && string(password) == expectedPass {
		_, err := conn.Write([]byte{0x01, 0x00})
		return err
	}

	conn.Write([]byte{0x01, 0x01})
	return fmt.Errorf("invalid username or password")
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
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	case 0x03:
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
		0x05,
		rep,
		0x00,
		0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	_, err := conn.Write(reply)
	return err
}

func relay(client net.Conn, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, client)

		if tcpConn, ok := target.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)

		if tcpConn, ok := client.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}
