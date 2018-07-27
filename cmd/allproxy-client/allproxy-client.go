package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/hillguo/allproxy"
)

func main() {
	var config string
	flag.StringVar(&config, "c", "allproxy.json", "allproxy.json path")
	flag.Parse()

	clientConfig := &allproxy.ClientConfig{}
	if _, err := os.Stat(config); err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}
	f, err := os.Open(config)
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}
	jsonconf, err := ioutil.ReadAll(f)
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}
	if err := json.Unmarshal(jsonconf, clientConfig); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	log.Printf("%v\n", *clientConfig)
	f.Close()
	proxyAddr = clientConfig.Server + ":" + strconv.Itoa(clientConfig.ServerPort)
	localListen, err := net.Listen("tcp", clientConfig.LocalAddress+":"+strconv.Itoa(clientConfig.LocalPort))

	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	for {
		conn, err := localListen.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		method := clientConfig.Method
		cipher, err := allproxy.NewCipher(method, clientConfig.PassWord)
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConn(conn, cipher)
	}
}

// Client type
const (
	HTTPType = iota
	Socks5   = 1
)

var (
	proxyNet  = "tcp"
	proxyAddr = ""
)

func handleConn(conn net.Conn, cipher *allproxy.Cipher) {

	defer func() {
		conn.Close()
	}()

	//创建与SOCKS5服务器的TCP连接后客户端需要先发送请求来协议版本及认证方式，格式为（以字节为单位）
	/*
		VER	NMETHODS	METHODS
		1	1	1-255
		VER是SOCKS版本，这里应该是0x05；
		NMETHODS是METHODS部分的长度；
		METHODS是客户端支持的认证方式列表，每个方法占1字节。当前的定义是：
		0x00 不需要认证
		0x01 GSSAPI
		0x02 用户名、密码认证
		0x03 - 0x7F由IANA分配（保留）
		0x80 - 0xFE为私人方法保留
		0xFF 无可接受的方法
	*/
	buf := make([]byte, 257)
	var err error
	if _, err = io.ReadFull(conn, buf[:2]); err != nil {
		log.Println(err)
		return
	}
	if buf[0] != 0x05 {
		//treat it as http or https
		// 解析到 host
		var httpRequestLine = make([]byte, 1024)
		copy(httpRequestLine[:2], buf[:2])

		log.Println(string(httpRequestLine[:2]))
		var hasreadn = 2
		for {
			n, err := conn.Read(httpRequestLine[hasreadn:])
			if err != nil {
				return
			}
			log.Println(string(httpRequestLine[:n+hasreadn]))
			i := bytes.IndexByte(httpRequestLine[:hasreadn+n], '\n')
			hasreadn += n
			if i != -1 {
				rqline := httpRequestLine[:i+1]
				//log.Println(string(rqline))
				muv := bytes.Split(rqline, []byte{' '})
				var httpMethod, httpHost, address string
				if len(muv) > 2 {
					httpMethod = string(muv[0])
					//log.Println(httpMethod)
					httpHost = string(muv[1])
					//log.Println(httpHost)
				} else {
					return
				}
				hostPortUrl, err := url.Parse(httpHost)
				if err != nil {
					log.Println(err)
					return
				}
				if hostPortUrl.Opaque == "443" {
					address = hostPortUrl.Scheme + ":443"
				} else {
					if strings.Index(hostPortUrl.Host, ":") == -1 {
						address = hostPortUrl.Host + ":80"
					} else {
						address = hostPortUrl.Host
					}
				}
				log.Println(address)

				scocks5, err := allproxy.ShadowSocks5Dial(cipher, proxyNet, proxyAddr, nil, allproxy.Direct)
				perHost := allproxy.NewPerHost(scocks5, scocks5)
				//perHost.AddFromString("202.197.74.49")

				remote, err := perHost.Dial("tcp", address)
				if err != nil {
					log.Println(err)
					return
				}
				defer func() {
					remote.Close()
				}()

				if httpMethod == "CONNECT" {
					_, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

					if err != nil {
						log.Println(err)
						return
					}
					//remote.Write(httpRequestLine[:hasreadn])
				} else {
					log.Println(string(httpRequestLine[:hasreadn]))
					remote.Write(httpRequestLine[:hasreadn])
				}
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
				break

			}
		}
		return
	}
	nmethod := int(buf[1])
	msgLen := nmethod + 2
	_, err = io.ReadFull(conn, buf[2:msgLen])
	if err != nil {
		log.Println(err)
		return
	}
	/*
		服务器从客户端提供的方法中选择一个并通过以下消息通知客户端（以字节为单位）：

		VER	METHOD
		1	1
		VER是SOCKS版本，这里应该是0x05；
		METHOD是服务端选中的方法。如果返回0xFF表示没有一个认证方法被选中，客户端需要关闭连接。
	*/
	_, err = conn.Write([]byte{0x05, 0})
	host, err := getRequest(conn)
	if err != nil {
		log.Println(err)
		return
	}
	_, err = askRequest(conn)
	if err != nil {
		log.Println(err)
		return
	}

	scocks5, err := allproxy.ShadowSocks5Dial(cipher, proxyNet, proxyAddr, nil, allproxy.Direct)
	perHost := allproxy.NewPerHost(scocks5, scocks5)
	perHost.AddFromString("*.google.com")
	perHost.AddFromString("*.youku.com")
	perHost.AddFromString("*.youtube.com")

	remote, err := perHost.Dial("tcp", host)
	if err != nil {
		log.Println(err)
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

/*
认证结束后客户端就可以发送请求信息。如果认证方法有特殊封装要求，请求必须按照方法所定义的方式进行封装。

SOCKS5请求格式（以字节为单位）：

VER	CMD	RSV	ATYP	DST.ADDR	DST.PORT
1	1	0x00	1	动态	2
VER是SOCKS版本，这里应该是0x05；
CMD是SOCK的命令码
0x01表示CONNECT请求
0x02表示BIND请求
0x03表示UDP转发
RSV 0x00，保留
ATYP DST.ADDR类型
0x01 IPv4地址，DST.ADDR部分4字节长度
0x03域名，DST ADDR部分第一个字节为域名长度，DST.ADDR剩余的内容为域名，没有\0结尾。
0x04 IPv6地址，16个字节长度。
DST.ADDR 目的地址
DST.PORT 网络字节序表示的目的端口
*/
func getRequest(conn net.Conn) (host string, err error) {

	buf := make([]byte, 300)
	if _, err = io.ReadFull(conn, buf[0:4]); err != nil {
		return
	}
	//log.Println(buf[0:4])
	if int(buf[0]) != 0x05 {
		err = errors.New("不支持的socks version")
		return
	}

	if buf[1] != 0x01 {
		err = errors.New("CMD error" + strconv.Itoa(int(buf[1])))
		return
	}

	reqLen := 0
	startIndex := 0
	domainLen := 0
	switch buf[3] {
	case 0x01:
		reqLen = net.IPv4len + 2 //DST.ADDR+DST.PORT
		startIndex = 4
	case 0x04:
		reqLen = net.IPv6len + 2 //DST.ADDR+DST.PORT
		startIndex = 4
	case 0x03:
		if _, err = io.ReadFull(conn, buf[4:5]); err != nil {
			return
		}
		domainLen = int(buf[4])
		reqLen = domainLen + 2
		startIndex = 5
	default:
		err = errors.New("unsupport addr type")
		return
	}
	if _, err = io.ReadFull(conn, buf[startIndex:reqLen+startIndex]); err != nil {
		return
	}

	switch buf[3] {
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

/*
服务器按以下格式回应客户端的请求（以字节为单位）：

VER	REP	RSV	ATYP	BND.ADDR	BND.PORT
1	1	0x00	1	动态	2
VER是SOCKS版本，这里应该是0x05；
REP应答字段
0x00表示成功
0x01普通SOCKS服务器连接失败
0x02现有规则不允许连接
0x03网络不可达
0x04主机不可达
0x05连接被拒
0x06 TTL超时
0x07不支持的命令
0x08不支持的地址类型
0x09 - 0xFF未定义
RSV 0x00，保留
ATYP BND.ADDR类型
0x01 IPv4地址，DST.ADDR部分4字节长度
0x03域名，DST.ADDR部分第一个字节为域名长度，DST.ADDR剩余的内容为域名，没有\0结尾。
0x04 IPv6地址，16个字节长度。
BND.ADDR 服务器绑定的地址
BND.PORT 网络字节序表示的服务器绑定的端口
*/
func askRequest(conn net.Conn) (n int, err error) {
	data := []byte{
		0x05,
		0x00,
		0x00,
		0x01,
		0x00,
		0x00,
		0x00,
		0x00,
		0x80,
		0x43,
	}
	return conn.Write(data)
}
