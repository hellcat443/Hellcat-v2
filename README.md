# Hellcat 2.0 — VLESS & Trojan traffic tester

Lightweight Go tool to generate realistic VLESS and Trojan traffic (TCP / WS, optional TLS) for testing your own servers. **Use only on infrastructure you own or are authorized to test.**

## Quick usage
# VLESS over TLS (TCP)
./hellcat -proto=vless -server=proxy.example.com -port=443 -mode=tcp -clients=10 -target=google.com:443

# Trojan with password
./hellcat -proto=trojan -server=trojan.example.com -port=443 -mode=tcp -clients=10 -target=google.com:443 -password=12345

## Flags
-server  (default 127.0.0.1)

-port    (default 443)

-tls     (default true)

-clients (default 5)

-idle    (seconds, default 0.2)

-mode    tcp|ws (default tcp)

-wspath  (WS path, default /vless)

-proto   vless|trojan (default vless)

-target  host:port (default google.com:443)

-password for trojan (optional)

## Notes
Intended for load/testing only.

Trojan flow: password + CRLF, then SOCKS5 CONNECT, then payload.

VLESS: minimal initial request (version, UUID, command, address) then payload.
