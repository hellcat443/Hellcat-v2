package main
 
import (
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
	"sync/atomic"
	"time"
 
	"github.com/gorilla/websocket"
)
 
var ScriptName = "hellcat v2.1"
var Protocols = []string{"vless", "trojan"}
 
type Config struct {
	Server    string
	Port      string
	UseTLS    bool
	Clients   int
	Duration  time.Duration
	Mode      string
	WSPath    string
	Proto     string
	Target    string
	Password  string
	Rate      int
	LoadType  string
	UUID      string
}
 
var (
	requestID    uint64
	successCount uint64
	failCount    uint64
	totalBytes   uint64
)
 
func main() {
	cfg := Config{}
	flag.StringVar(&cfg.Server, "server", "127.0.0.1", "Server address")
	flag.StringVar(&cfg.Port, "port", "443", "Server port")
	flag.BoolVar(&cfg.UseTLS, "tls", true, "Use TLS/WSS")
	flag.IntVar(&cfg.Clients, "clients", 50, "Number of concurrent clients")
	flag.DurationVar(&cfg.Duration, "duration", 30*time.Second, "Test duration")
	flag.StringVar(&cfg.Mode, "mode", "tcp", "Mode: tcp, ws, syn, ack, flood")
	flag.StringVar(&cfg.WSPath, "wspath", "/", "WebSocket path")
	flag.StringVar(&cfg.Proto, "proto", "vless", "Protocol: vless or trojan")
	flag.StringVar(&cfg.Target, "target", "google.com:443", "Target host:port")
	flag.StringVar(&cfg.Password, "password", "", "Password for trojan")
	flag.IntVar(&cfg.Rate, "rate", 1000, "Maximum requests per second")
	flag.StringVar(&cfg.LoadType, "load", "handshake", "Load type: syn, ack, handshake, flood, mixed")
	flag.StringVar(&cfg.UUID, "uuid", "", "UUID for vless (auto-generated if empty)")
 
	flag.Parse()
 
	
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
 
	
	if cfg.Proto == "trojan" && cfg.Password == "" {
		cfg.Password = GenerateRandomPassword(16)
		logf("Generated random password for trojan: %s", cfg.Password)
	}
 
	if cfg.UUID == "" {
		cfg.UUID = GenerateUUIDv4()
		logf("Generated UUID: %s", cfg.UUID)
	}
 
	rand.Seed(time.Now().UnixNano())
 
	logf("Starting %s load test [%s/%s]", cfg.LoadType, cfg.Proto, cfg.Mode)
	logf("Target: %s:%s, Clients: %d, Duration: %v", cfg.Server, cfg.Port, cfg.Clients, cfg.Duration)
	logf("Rate: %d/sec, UUID: %s", cfg.Rate, cfg.UUID)
 
	
	startTime := time.Now()
	var wg sync.WaitGroup
	stopChan := make(chan struct{})
	rateLimiter := make(chan struct{}, cfg.Rate)
 
	
	go func() {
		for {
			select {
			case rateLimiter <- struct{}{}:
				time.Sleep(time.Second / time.Duration(cfg.Rate))
			case <-stopChan:
				return
			}
		}
	}()
 
	
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
 
		for {
			select {
			case <-ticker.C:
				success := atomic.LoadUint64(&successCount)
				fail := atomic.LoadUint64(&failCount)
				bytes := atomic.LoadUint64(&totalBytes)
				elapsed := time.Since(startTime).Seconds()
 
				logf("STATS: Success=%d, Fail=%d, Bytes=%d, RPS=%.1f", 
					success, fail, bytes, float64(success+fail)/elapsed)
			case <-stopChan:
				return
			}
		}
	}()
 
	
	for i := 0; i < cfg.Clients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			worker(cfg, clientID, stopChan, rateLimiter)
		}(i)
	}
 
	
	time.AfterFunc(cfg.Duration, func() {
		close(stopChan)
		logf("Test duration reached, stopping...")
	})
 
	wg.Wait()
	totalTime := time.Since(startTime)
 
	
	success := atomic.LoadUint64(&successCount)
	fail := atomic.LoadUint64(&failCount)
	bytes := atomic.LoadUint64(&totalBytes)
	total := success + fail
 
	logf("=== FINAL RESULTS ===")
	logf("Duration: %v", totalTime)
	logf("Total Requests: %d", total)
	logf("Successful: %d (%.1f%%)", success, float64(success)/float64(total)*100)
	logf("Failed: %d (%.1f%%)", fail, float64(fail)/float64(total)*100)
	logf("Total Bytes: %d", bytes)
	logf("Average RPS: %.1f", float64(total)/totalTime.Seconds())
}
 
func worker(cfg Config, clientID int, stopChan <-chan struct{}, rateLimiter <-chan struct{}) {
	for {
		select {
		case <-stopChan:
			return
		case <-rateLimiter:
			
		}
 
		reqID := atomic.AddUint64(&requestID, 1)
		var success bool
		var bytes int
 
		
		loadType := cfg.LoadType
		if loadType == "mixed" {
			types := []string{"syn", "ack", "handshake", "flood"}
			loadType = types[rand.Intn(len(types))]
		}
 
		switch loadType {
		case "syn":
			success, bytes = sendSYN(cfg, clientID, reqID)
		case "ack":
			success, bytes = sendACK(cfg, clientID, reqID)
		case "handshake":
			success, bytes = sendHandshake(cfg, clientID, reqID)
		case "flood":
			success, bytes = sendFlood(cfg, clientID, reqID)
		default:
			success, bytes = sendHandshake(cfg, clientID, reqID)
		}
 
		if success {
			atomic.AddUint64(&successCount, 1)
			atomic.AddUint64(&totalBytes, uint64(bytes))
		} else {
			atomic.AddUint64(&failCount, 1)
		}
	}
}
 

 
func handleVLESSHandshake(conn net.Conn, uuid, targetHost string, targetPort uint16) (bool, int) {
	bytesSent := 0
 
	
	handshake, err := BuildVLESSRequest(uuid, targetHost, targetPort)
	if err != nil {
		logf("VLESS handshake build failed: %v", err)
		return false, 0
	}
 
	n, err := conn.Write(handshake)
	if err != nil {
		return false, 0
	}
	bytesSent += n
 
	
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 64)
	n, err = conn.Read(buffer)
	if err != nil {
		return false, bytesSent
	}
 
	
	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: proxy-tester\r\nConnection: close\r\n\r\n", targetHost)
	n, err = conn.Write([]byte(httpReq))
	if err != nil {
		return false, bytesSent
	}
	bytesSent += n
 
	
	totalRead := 0
	for {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buffer)
		if n > 0 {
			totalRead += n
		}
		if err != nil {
			break
		}
	}
 
	return true, bytesSent + totalRead
}
 

 
func handleTrojanHandshake(conn net.Conn, password, targetHost string, targetPort uint16) (bool, int) {
	bytesSent := 0
 
	
	passwordLine := password + "\r\n"
	n, err := conn.Write([]byte(passwordLine))
	if err != nil {
		return false, 0
	}
	bytesSent += n
 
	
	socks5Request := buildTrojanSocks5Request(targetHost, targetPort)
	n, err = conn.Write(socks5Request)
	if err != nil {
		return false, bytesSent
	}
	bytesSent += n
 
	
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	socks5Response := make([]byte, 10)
	n, err = conn.Read(socks5Response)
	if err != nil {
		return false, bytesSent
	}
 
	
	if n < 2 || socks5Response[1] != 0x00 {
		return false, bytesSent
	}
 
	
	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: trojan-tester\r\nConnection: close\r\n\r\n", targetHost)
	n, err = conn.Write([]byte(httpReq))
	if err != nil {
		return false, bytesSent
	}
	bytesSent += n
 
	
	totalRead := 0
	buffer := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buffer)
		if n > 0 {
			totalRead += n
		}
		if err != nil {
			break
		}
	}
 
	return true, bytesSent + totalRead
}
 

 
func handleVLESSWebSocketHandshake(conn *websocket.Conn, uuid, targetHost string, targetPort uint16) (bool, int) {
	bytesSent := 0

	
	handshake, err := BuildVLESSRequest(uuid, targetHost, targetPort)
	if err != nil {
		return false, 0
	}

	err = conn.WriteMessage(websocket.BinaryMessage, handshake)
	if err != nil {
		return false, 0
	}
	bytesSent += len(handshake)

	
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err = conn.ReadMessage() 
	if err != nil {
		return false, bytesSent
	}

	
	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", targetHost)
	err = conn.WriteMessage(websocket.BinaryMessage, []byte(httpReq))
	if err != nil {
		return false, bytesSent
	}
	bytesSent += len(httpReq)

	
	totalRead := 0
	for {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		totalRead += len(message)
	}

	return true, bytesSent + totalRead
}

 
func handleTrojanWebSocketHandshake(conn *websocket.Conn, password, targetHost string, targetPort uint16) (bool, int) {
	bytesSent := 0
 
	
	passwordLine := password + "\r\n"
	err := conn.WriteMessage(websocket.BinaryMessage, []byte(passwordLine))
	if err != nil {
		return false, 0
	}
	bytesSent += len(passwordLine)
 
	
	socks5Request := buildTrojanSocks5Request(targetHost, targetPort)
	err = conn.WriteMessage(websocket.BinaryMessage, socks5Request)
	if err != nil {
		return false, bytesSent
	}
	bytesSent += len(socks5Request)
 
	
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, response, err := conn.ReadMessage()
	if err != nil {
		return false, bytesSent
	}
 
	
	if len(response) < 2 || response[1] != 0x00 {
		return false, bytesSent
	}
 
	
	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", targetHost)
	err = conn.WriteMessage(websocket.BinaryMessage, []byte(httpReq))
	if err != nil {
		return false, bytesSent
	}
	bytesSent += len(httpReq)
 
	
	totalRead := 0
	for {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		totalRead += len(message)
	}
 
	return true, bytesSent + totalRead
}
 

 
func sendSYN(cfg Config, clientID int, reqID uint64) (bool, int) {
	addr := fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
 
	var conn net.Conn
	var err error
 
	if cfg.UseTLS && (cfg.Mode == "tcp" || cfg.Mode == "syn") {
		sni := GenerateRandomSNI()
		conn, err = tls.Dial("tcp", addr, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = net.DialTimeout("tcp", addr, 1*time.Second)
	}
 
	if err != nil {
		return false, 0
	}
 
	
	if cfg.Proto == "vless" {
		uuidBytes := []byte(cfg.UUID)
		conn.Write(uuidBytes)
	} else if cfg.Proto == "trojan" {
		passwordLine := cfg.Password + "\r\n"
		conn.Write([]byte(passwordLine))
	}
 
	conn.Close()
	return true, len(cfg.UUID)
}
 
func sendACK(cfg Config, clientID int, reqID uint64) (bool, int) {
	if cfg.Mode == "ws" {
		return sendWSACK(cfg, clientID, reqID)
	}
 
	addr := fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
	var conn net.Conn
	var err error
 
	if cfg.UseTLS {
		sni := GenerateRandomSNI()
		conn, err = tls.Dial("tcp", addr, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = net.DialTimeout("tcp", addr, 2*time.Second)
	}
 
	if err != nil {
		return false, 0
	}
	defer conn.Close()
 
	
	var message string
	if cfg.Proto == "vless" {
		message = fmt.Sprintf("ACK-%d-UUID:%s", reqID, cfg.UUID)
	} else {
		message = fmt.Sprintf("ACK-%d-PASSWORD:%s", reqID, cfg.Password)
	}
 
	_, err = conn.Write([]byte(message))
	if err != nil {
		return false, 0
	}
 
	
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buffer := make([]byte, 1024)
	n, _ := conn.Read(buffer)
 
	return true, len(message) + n
}
 
func sendHandshake(cfg Config, clientID int, reqID uint64) (bool, int) {
	if cfg.Mode == "ws" {
		return sendWSHandshake(cfg, clientID, reqID)
	}
 
	addr := fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
	var conn net.Conn
	var err error
 
	if cfg.UseTLS {
		sni := GenerateRandomSNI()
		conn, err = tls.Dial("tcp", addr, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = net.DialTimeout("tcp", addr, 3*time.Second)
	}
 
	if err != nil {
		return false, 0
	}
	defer conn.Close()
 
	targetHost, targetPort, err := parseTarget(cfg.Target)
	if err != nil {
		return false, 0
	}
 
	
	if cfg.Proto == "vless" {
		return handleVLESSHandshake(conn, cfg.UUID, targetHost, targetPort)
	} else {
		return handleTrojanHandshake(conn, cfg.Password, targetHost, targetPort)
	}
}
 
func sendWSHandshake(cfg Config, clientID int, reqID uint64) (bool, int) {
	scheme := "ws"
	if cfg.UseTLS {
		scheme = "wss"
	}
 
	sni := GenerateRandomSNI()
	wsPath := GenerateRandomWSPath(cfg.WSPath)
	u := url.URL{Scheme: scheme, Host: fmt.Sprintf("%s:%s", cfg.Server, cfg.Port), Path: wsPath}
 
	dialer := websocket.Dialer{
		HandshakeTimeout: 3 * time.Second,
	}
	if cfg.UseTLS {
		dialer.TLSClientConfig = &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		}
	}
 
	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return false, 0
	}
	defer conn.Close()
 
	targetHost, targetPort, err := parseTarget(cfg.Target)
	if err != nil {
		return false, 0
	}
 
	
	if cfg.Proto == "vless" {
		return handleVLESSWebSocketHandshake(conn, cfg.UUID, targetHost, targetPort)
	} else {
		return handleTrojanWebSocketHandshake(conn, cfg.Password, targetHost, targetPort)
	}
}
 
func sendFlood(cfg Config, clientID int, reqID uint64) (bool, int) {
	if cfg.Mode == "ws" {
		return sendWSFlood(cfg, clientID, reqID)
	}
 
	addr := fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
	var conn net.Conn
	var err error
 
	if cfg.UseTLS {
		conn, err = tls.Dial("tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = net.DialTimeout("tcp", addr, 1*time.Second)
	}
 
	if err != nil {
		return false, 0
	}
 
	
	var message string
	if cfg.Proto == "vless" {
		message = fmt.Sprintf("FLOOD-%d-%s", reqID, cfg.UUID)
	} else {
		message = fmt.Sprintf("FLOOD-%d-%s", reqID, cfg.Password)
	}
 
	conn.Write([]byte(message))
	conn.Close()
 
	return true, len(message)
}
 
func sendWSACK(cfg Config, clientID int, reqID uint64) (bool, int) {
	scheme := "ws"
	if cfg.UseTLS {
		scheme = "wss"
	}
 
	sni := GenerateRandomSNI()
	wsPath := GenerateRandomWSPath(cfg.WSPath)
	u := url.URL{Scheme: scheme, Host: fmt.Sprintf("%s:%s", cfg.Server, cfg.Port), Path: wsPath}
 
	dialer := websocket.Dialer{
		HandshakeTimeout: 2 * time.Second,
	}
	if cfg.UseTLS {
		dialer.TLSClientConfig = &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		}
	}
 
	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return false, 0
	}
	defer conn.Close()
 
	
	var message string
	if cfg.Proto == "vless" {
		message = fmt.Sprintf("WS-ACK-%d-%s", reqID, cfg.UUID)
	} else {
		message = fmt.Sprintf("WS-ACK-%d-%s", reqID, cfg.Password)
	}
 
	err = conn.WriteMessage(websocket.BinaryMessage, []byte(message))
	if err != nil {
		return false, 0
	}
 
	
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, response, _ := conn.ReadMessage()
 
	return true, len(message) + len(response)
}
 
func sendWSFlood(cfg Config, clientID int, reqID uint64) (bool, int) {
	scheme := "ws"
	if cfg.UseTLS {
		scheme = "wss"
	}
 
	wsPath := GenerateRandomWSPath(cfg.WSPath)
	u := url.URL{Scheme: scheme, Host: fmt.Sprintf("%s:%s", cfg.Server, cfg.Port), Path: wsPath}
 
	dialer := websocket.Dialer{
		HandshakeTimeout: 1 * time.Second,
	}
	if cfg.UseTLS {
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
 
	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return false, 0
	}
 
	var message string
	if cfg.Proto == "vless" {
		message = fmt.Sprintf("WS-FLOOD-%d-%s", reqID, cfg.UUID)
	} else {
		message = fmt.Sprintf("WS-FLOOD-%d-%s", reqID, cfg.Password)
	}
 
	conn.WriteMessage(websocket.BinaryMessage, []byte(message))
	conn.Close()
 
	return true, len(message)
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
	packet = append(packet, 0x00)         
	packet = append(packet, uuidBytes...) 
	packet = append(packet, 0x00)         
	packet = append(packet, 0x01)         
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
 
func buildTrojanSocks5Request(host string, port uint16) []byte {
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
	return s1 + ".com"
}
 
func GenerateRandomWSPath(base string) string {
	letters := "abcdefghijklmnopqrstuvwxyz0123456789"
	length := rand.Intn(5) + 3
	path := base
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
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
 
func logf(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("[%s] %s\n", ScriptName, msg)
}
