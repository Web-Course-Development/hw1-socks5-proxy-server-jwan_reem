package main

import (
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
		// 0xFF means no acceptable authentication methods
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
}
