package main

import (
	"bufio"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var ScriptName = "hellcat v2"
var Protocols = []string{"vless", "trojan"}

// made by hellcat443

type Config struct {
	Server   string
	Port     string
	UseTLS   bool
	Clients  int
	Idle     float64
	Mode     string 
	WSPath   string
	Proto    string
	Target   string
	Password string 
}

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.Server, "server", "127.0.0.1", "Server address")
	flag.StringVar(&cfg.Port, "port", "443", "Server port")
	flag.BoolVar(&cfg.UseTLS, "tls", true, "Use TLS/WSS")
	flag.IntVar(&cfg.Clients, "clients", 5, "Number of concurrent clients")
	flag.Float64Var(&cfg.Idle, "idle", 0.2, "Seconds between reconnects")
	flag.StringVar(&cfg.Mode, "mode", "tcp", "Mode: tcp or ws")
	flag.StringVar(&cfg.WSPath, "wspath", "/vless", "Base WebSocket path")
	flag.StringVar(&cfg.Proto, "proto", "vless", "Protocol: vless or trojan")
	flag.StringVar(&cfg.Target, "target", "google.com:443", "Target host:port to request via proxy")
	flag.StringVar(&cfg.Password, "password", "", "Password for trojan (if required)")
	flag.Parse()

	if cfg.Proto == "trojan" && cfg.Password == "" {
		cfg.Password = GenerateRandomPassword(16)
		logf("Generated random password for trojan: %s", cfg.Password)
	}

	
	valid := false
	for _, p := range Protocols {
		if p == cfg.Proto {
			valid = true
			break
		}
	}
	if !valid {
		logf("Invalid protocol '%s', choose from: vless, trojan", cfg.Proto)
		return
	}

	rand.Seed(time.Now().UnixNano())
	var wg sync.WaitGroup

	logf("Starting persistent %s test (%s): %d clients → %s:%s (target=%s)",
		cfg.Mode, cfg.Proto, cfg.Clients, cfg.Server, cfg.Port, cfg.Target)

	for i := 0; i < cfg.Clients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			for {
				uuid := GenerateUUIDv4()
				sni := GenerateRandomSNI()
				wsPath := cfg.WSPath
				if cfg.Mode == "ws" {
					wsPath = GenerateRandomWSPath(cfg.WSPath)
				}
				if cfg.Mode == "tcp" {
					RunTCPClient(cfg, clientID, uuid, sni)
				} else {
					RunWSClient(cfg, clientID, uuid, sni, wsPath)
				}
				time.Sleep(time.Duration(cfg.Idle * float64(time.Second)))
			}
		}(i)
	}

	wg.Wait()
}


func RunTCPClient(cfg Config, clientID int, uuid, sni string) {
	addr := fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
	var conn net.Conn
	var err error

	if cfg.UseTLS {
		conn, err = tls.Dial("tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	} else {
		conn, err = net.Dial("tcp", addr)
	}

	if err != nil {
		logf("[%s TCP Client %d] connect failed: %v (SNI=%s)", cfg.Proto, clientID, err, sni)
		time.Sleep(1 * time.Second)
		return
	}
	defer conn.Close()

	targetHost, targetPort, perr := parseTarget(cfg.Target)
	if perr != nil {
		logf("[%s TCP Client %d] invalid target '%s': %v", cfg.Proto, clientID, cfg.Target, perr)
		return
	}

	switch cfg.Proto {
	case "vless":
		handshake, err := BuildVLESSRequest(uuid, targetHost, targetPort)
		if err != nil {
			logf("[vless TCP Client %d] failed to build handshake: %v", clientID, err)
			return
		}
		if _, err := conn.Write(handshake); err != nil {
			logf("[vless TCP Client %d] handshake write failed: %v", clientID, err)
			return
		}
		httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetHost)
		conn.Write([]byte(httpReq))
		logf("[vless TCP Client %d] sent handshake+GET (target=%s:%d)", clientID, targetHost, targetPort)

	case "trojan":
		pwLine := cfg.Password + "\r\n"
		if _, err := conn.Write([]byte(pwLine)); err != nil {
			logf("[trojan TCP Client %d] write password failed: %v", clientID, err)
			return
		}
		if err := sendSocks5ConnectConn(conn, targetHost, targetPort); err != nil {
			logf("[trojan TCP Client %d] socks5 connect failed: %v", clientID, err)
			return
		}
		httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetHost)
		conn.Write([]byte(httpReq))
		logf("[trojan TCP Client %d] trojan password + socks5 + GET sent (target=%s:%d)", clientID, targetHost, targetPort)

	default:
		logf("[TCP Client %d] unknown proto %s", clientID, cfg.Proto)
		return
	}

	reader := bufio.NewReader(conn)
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	total := 0
	for {
		n, rerr := reader.Read(buf)
		if n > 0 {
			total += n
			if total <= 10240 {
				logf("[%s TCP Client %d] recv %d bytes", cfg.Proto, clientID, n)
			}
		}
		if rerr != nil {
			break
		}
	}
	logf("[%s TCP Client %d] done (total recv %d bytes)", cfg.Proto, clientID, total)
}


func RunWSClient(cfg Config, clientID int, uuid, sni, wsPath string) {
	scheme := "ws"
	if cfg.UseTLS {
		scheme = "wss"
	}
	u := url.URL{Scheme: scheme, Host: fmt.Sprintf("%s:%s", cfg.Server, cfg.Port), Path: wsPath}
	dialer := websocket.Dialer{}
	if cfg.UseTLS {
		dialer.TLSClientConfig = &tls.Config{ServerName: sni, InsecureSkipVerify: true}
	}

	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		logf("[%s WS Client %d] connect failed: %v (SNI=%s, Path=%s)", cfg.Proto, clientID, err, sni, wsPath)
		time.Sleep(1 * time.Second)
		return
	}
	defer conn.Close()

	targetHost, targetPort, perr := parseTarget(cfg.Target)
	if perr != nil {
		logf("[%s WS Client %d] invalid target '%s': %v", cfg.Proto, clientID, cfg.Target, perr)
		return
	}

	switch cfg.Proto {
	case "vless":
		handshake, err := BuildVLESSRequest(uuid, targetHost, targetPort)
		if err != nil {
			logf("[vless WS Client %d] failed to build handshake: %v", clientID, err)
			return
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, handshake); err != nil {
			logf("[vless WS Client %d] handshake write failed: %v", clientID, err)
			return
		}
		httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetHost)
		conn.WriteMessage(websocket.BinaryMessage, []byte(httpReq))
		logf("[vless WS Client %d] sent handshake+GET (target=%s:%d)", clientID, targetHost, targetPort)

	case "trojan":
		pwLine := cfg.Password + "\r\n"
		if err := conn.WriteMessage(websocket.BinaryMessage, []byte(pwLine)); err != nil {
			logf("[trojan WS Client %d] write password failed: %v", clientID, err)
			return
		}
		socksReq := buildSocks5ConnectBytes(targetHost, targetPort)
		if err := conn.WriteMessage(websocket.BinaryMessage, socksReq); err != nil {
			logf("[trojan WS Client %d] write socks5 failed: %v", clientID, err)
			return
		}
		httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetHost)
		conn.WriteMessage(websocket.BinaryMessage, []byte(httpReq))
		logf("[trojan WS Client %d] trojan password + socks5 + GET sent (target=%s:%d)", clientID, targetHost, targetPort)

	default:
		logf("[WS Client %d] unknown proto %s", clientID, cfg.Proto)
		return
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, message, rerr := conn.ReadMessage()
		if rerr != nil {
			break
		}
		logf("[%s WS Client %d] recv %d bytes", cfg.Proto, clientID, len(message))
	}
	logf("[%s WS Client %d] ws done", cfg.Proto, clientID)
}


func GenerateUUIDv4() string {
	b := make([]byte, 16)
	crand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func GenerateRandomSNI() string {
	letters := "abcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"
	len1 := rand.Intn(5) + 3
	len2 := rand.Intn(3) + 2

	s1 := ""
	for i := 0; i < len1; i++ {
		s1 += string(letters[rand.Intn(len(letters))])
	}
	for i := 0; i < len2; i++ {
		s1 += string(digits[rand.Intn(len(digits))])
	}
	return s1 + ".test"
}

func GenerateRandomWSPath(base string) string {
	letters := "abcdefghijklmnopqrstuvwxyz0123456789"
	length := rand.Intn(5) + 3
	path := base
	for i := 0; i < length; i++ {
		path += string(letters[rand.Intn(len(letters))])
	}
	return path
}

func GenerateRandomPassword(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if length <= 0 {
		length = 16
	}
	b := make([]byte, length)
	random := make([]byte, length)
	_, _ = crand.Read(random)
	for i := 0; i < length; i++ {
		b[i] = chars[int(random[i])%len(chars)]
	}
	return string(b)
}



func BuildVLESSRequest(uuid, targetHost string, targetPort uint16) ([]byte, error) {
	uuidBytes, err := hex.DecodeString(removeDash(uuid))
	if err != nil {
		return nil, err
	}
	if len(uuidBytes) != 16 {
		return nil, fmt.Errorf("uuid bytes length != 16")
	}

	packet := make([]byte, 0, 64)
	packet = append(packet, 0x00)         // version
	packet = append(packet, uuidBytes...) // uuid
	packet = append(packet, 0x00)         // addons
	packet = append(packet, 0x01)         // connect
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, targetPort)
	packet = append(packet, portBytes...)

	ip := net.ParseIP(targetHost)
	if ip != nil {
		if ip.To4() != nil {
			packet = append(packet, 0x01)
			packet = append(packet, ip.To4()...)
		} else {
			packet = append(packet, 0x03)
			packet = append(packet, ip.To16()...)
		}
	} else {
		if len(targetHost) > 255 {
			return nil, fmt.Errorf("domain name too long")
		}
		packet = append(packet, 0x02)
		packet = append(packet, byte(len(targetHost)))
		packet = append(packet, []byte(targetHost)...)
	}
	return packet, nil
}

func BuildRandomPacket() []byte {
	size := rand.Intn(128) + 16
	pkt := make([]byte, size)
	crand.Read(pkt)
	return pkt
}

func removeDash(s string) string {
	res := ""
	for _, c := range s {
		if c != '-' {
			res += string(c)
		}
	}
	return res
}

func parseTarget(t string) (host string, port uint16, err error) {
	if strings.HasPrefix(t, "[") {
		idx := strings.LastIndex(t, "]")
		if idx == -1 {
			return "", 0, fmt.Errorf("invalid ipv6 format")
		}
		host = t[1:idx]
		rest := t[idx+1:]
		if strings.HasPrefix(rest, ":") {
			p, perr := strconv.Atoi(rest[1:])
			if perr != nil {
				return "", 0, perr
			}
			return host, uint16(p), nil
		}
		return "", 0, fmt.Errorf("missing port")
	}
	parts := strings.Split(t, ":")
	if len(parts) < 2 {
		return "", 0, fmt.Errorf("target must be host:port")
	}
	portNum, perr := strconv.Atoi(parts[len(parts)-1])
	if perr != nil {
		return "", 0, perr
	}
	host = strings.Join(parts[:len(parts)-1], ":")
	return host, uint16(portNum), nil
}

func buildSocks5ConnectBytes(host string, port uint16) []byte {
buf := make([]byte, 0, 8+len(host))
buf = append(buf, 0x05, 0x01, 0x00) 
ip := net.ParseIP(host)
if ip != nil {
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, 0x01)
		buf = append(buf, ip4...)
	} else {
		buf = append(buf, 0x04)
		buf = append(buf, ip.To16()...)
	}
} else {
	buf = append(buf, 0x03)
	buf = append(buf, byte(len(host)))
	buf = append(buf, []byte(host)...)
}
portBytes := make([]byte, 2)
binary.BigEndian.PutUint16(portBytes, port)
buf = append(buf, portBytes...)
return buf
}

func sendSocks5ConnectConn(conn net.Conn, host string, port uint16) error {
	req := buildSocks5ConnectBytes(host, port)
_, err := conn.Write(req)
return err
}

func logf(format string, a ...interface{}) {
msg := fmt.Sprintf(format, a...)
fmt.Printf("[%s] %s\n", ScriptName, msg)
}
