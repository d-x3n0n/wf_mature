package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
)

// StartSyslogServer starts the UDP listener and — if TCPPort > 0 — a TCP
// listener as well. The TCP listener handles one goroutine per connection
// and reads newline-delimited syslog frames (RFC3164/5424 or plain lines).
func StartSyslogServer(p *Pipeline) {
	if p.cfg.TCPPort > 0 {
		go startTCP(p)
	}
	startUDP(p) // blocks forever
}

// ── UDP ───────────────────────────────────────────────────────────────────────

func startUDP(p *Pipeline) {
	addr := &net.UDPAddr{Port: p.cfg.Port, IP: net.ParseIP("0.0.0.0")}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("[syslog] bind UDP :%d: %v", p.cfg.Port, err)
	}
	defer conn.Close()
	log.Printf("[syslog] listening on UDP :%d", p.cfg.Port)

	buf := make([]byte, 65535)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[syslog] UDP read error: %v", err)
			continue
		}
		raw := strings.TrimSpace(string(buf[:n]))
		if raw != "" {
			handleLog(p, raw, remote.IP.String())
		}
	}
}

// ── TCP ───────────────────────────────────────────────────────────────────────

func startTCP(p *Pipeline) {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", p.cfg.TCPPort))
	if err != nil {
		log.Fatalf("[syslog] bind TCP :%d: %v", p.cfg.TCPPort, err)
	}
	defer ln.Close()
	log.Printf("[syslog] listening on TCP :%d", p.cfg.TCPPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[syslog] TCP accept error: %v", err)
			continue
		}
		go handleTCPConn(p, conn)
	}
}

func handleTCPConn(p *Pipeline, conn net.Conn) {
	defer conn.Close()
	ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	// 256 KB per line — enough for the largest firewall log lines
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if raw != "" {
			handleLog(p, raw, ip)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[syslog] TCP read error (%s): %v", ip, err)
	}
}

// ── shared log handler ────────────────────────────────────────────────────────

func handleLog(p *Pipeline, raw, location string) {
	event, alerts := p.Process(raw, location)

	if event.DecoderFamily == "" {
		log.Printf("[recv] %-18s NO_DECODER  %.80s", location, raw)
		return
	}

	if len(alerts) == 0 {
		return
	}

	for _, r := range alerts {
		desc := resolveDesc(r.Description, event)
		src := event.SrcIP
		if src == "" {
			src = event.Location
		}
		log.Printf("[%s] rule=%-5d level=%-2d  src=%-18s  %s",
			levelLabel(r.Level), r.ID, r.Level, src, desc)
	}
}

func levelLabel(lvl int) string {
	switch {
	case lvl >= 12:
		return "CRITICAL"
	case lvl >= 8:
		return "HIGH    "
	case lvl >= 6:
		return "MEDIUM  "
	case lvl >= 4:
		return "LOW     "
	default:
		return "INFO    "
	}
}
