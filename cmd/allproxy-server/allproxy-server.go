package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/hillguo/allproxy"
)

func main() {

	ln, err := net.Listen("tcp", "0.0.0.0:8002")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	_, err = net.Dial("tcp", "baidu.com:80")
	log.Println("dial ", "14.215.177.39:80")
	if err != nil {
		fmt.Println(err)
		return
	} else {
		fmt.Println("ok")
		return
	}
	for {
		conn, err := ln.Accept()

		if err != nil {
			fmt.Println(err)
			continue
		}
		method := "aes-256-cfb"
		cipher, _ := allproxy.NewCipher(method, "h2san")
		go handleConnection(conn, cipher)
	}
}

func handleConnection(c net.Conn, cipher *allproxy.Cipher) {
	conn := allproxy.NewConn(c, cipher)
	defer func() {
		conn.Close()
	}()

	host, err := getRequest(conn)
	if err != nil {
		fmt.Println(err)
		return
	}

	remote, err := net.Dial("tcp", host)
	log.Println("dial ", host)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() {
		remote.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Add(-1)
		allproxy.PipeThenClose(remote, conn)
	}()

	wg.Add(1)
	go func() {
		defer wg.Add(-1)
		allproxy.PipeThenClose(conn, remote)
	}()
	wg.Wait()
}

func getRequest(conn net.Conn) (host string, err error) {

	buf := make([]byte, 300)
	//读地址类型
	if _, err = io.ReadFull(conn, buf[0:1]); err != nil {
		return
	}

	reqLen := 0
	startIndex := 0
	domainLen := 0
	addrType := buf[0]
	switch addrType {
	case 0x01:
		reqLen = net.IPv4len + 2 //DST.ADDR+DST.PORT
		startIndex = 1
	case 0x04:
		reqLen = net.IPv6len + 2 //DST.ADDR+DST.PORT
		startIndex = 1
	case 0x03:
		if _, err = io.ReadFull(conn, buf[1:2]); err != nil {
			return
		}
		domainLen = int(buf[1])
		reqLen = domainLen + 2
		startIndex = 2
	default:
		err = errors.New("unsupport addr type")
		return
	}
	if _, err = io.ReadFull(conn, buf[startIndex:reqLen+startIndex]); err != nil {
		return
	}

	switch addrType {
	case 0x01:
		host = net.IP(buf[startIndex : net.IPv4len+startIndex]).String()
	case 0x04:
		host = net.IP(buf[startIndex : net.IPv6len+startIndex]).String()
	case 0x03:
		host = string(buf[startIndex : startIndex+domainLen])
	}
	port := binary.BigEndian.Uint16(buf[startIndex+reqLen-2 : startIndex+reqLen])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}
