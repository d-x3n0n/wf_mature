package main

import (
	"strings"
	"time"
)

// PreDecode is Phase 1 — parses syslog envelope and KV fields.
// For Fortigate logs it also normalizes quoted KV values for decoder matching.
func PreDecode(raw string, event *Event) {
	s := strings.TrimSpace(raw)
	if s == "" {
		event.Message = s
		return
	}

	// Strip syslog PRI: <NN>
	body := s
	if len(body) > 0 && body[0] == '<' {
		if end := strings.IndexByte(body, '>'); end != -1 {
			body = body[end+1:]
		}
	}

	// Store the full body AFTER PRI strip but BEFORE envelope parsing.
	// Decoder prematch runs against event.Message (stripped), but some decoders
	// (e.g. CheckPoint) expect the full line including the syslog header fields.
	// We store it so RunDecoders can fall back to it when message-based prematch fails.
	event.RawBody = body

	// RFC 5424: "1 TIMESTAMP HOSTNAME ..."
	if strings.HasPrefix(body, "1 ") {
		parseRFC5424(body[2:], event)
		goto kv
	}

	// RFC 3164: "Mon DD HH:MM:SS HOST PROG: MSG"
	// Strict check: token[3] must look like a hostname (no colons, no %, no =)
	if parseRFC3164(body, event) {
		goto kv
	}

	// Bare PROG[PID]: MSG format — e.g. "sshd[1234]: Failed password..."
	// Handles logs sent without a syslog timestamp/hostname envelope.
	// Extract program_name so program_name-based decoders (sshd, etc.) can fire.
	if parseBareProgMsg(body, event) {
		goto kv
	}

	// Bare log (Fortigate, Cisco IOS, etc.) — no envelope
	event.Message = body
	if h := kvGet(body, "devname"); h != "" {
		event.Hostname = h
	}

kv:
	if event.Message == "" {
		return
	}

	// Full KV parse for the "data" output block
	for k, v := range ParseKV(event.Message) {
		event.KVFields[k] = v
	}

	// Promote user → dstuser (Wazuh behavior confirmed from real output)
	if u, ok := event.KVFields["user"]; ok && u != "" {
		event.DstUser = u
		event.KVFields["dstuser"] = u
	}

	// Normalize quoted KV values for decoder matching (FOS6/7 compat)
	event.NormalMessage = stripKVQuotes(event.Message)
}

// stripKVQuotes removes double-quotes from KV values:
//   devname="PNL-FortiGate-60F" → devname=PNL-FortiGate-60F
func stripKVQuotes(s string) string {
	if !strings.Contains(s, `="`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i, n := 0, len(s)
	for i < n {
		eq := strings.Index(s[i:], `="`)
		if eq == -1 {
			b.WriteString(s[i:])
			break
		}
		eq += i
		b.WriteString(s[i : eq+1])
		i = eq + 2
		j := i
		for j < n {
			if s[j] == '"' && (j+1 >= n || s[j+1] == ' ' || s[j+1] == '\t') {
				break
			}
			j++
		}
		b.WriteString(s[i:j])
		if j < n && s[j] == '"' {
			j++
		}
		i = j
	}
	return b.String()
}

// ─── RFC 5424 ─────────────────────────────────────────────────────────────────

// findSDEnd finds the end position of RFC5424 Structured Data (SD) blocks.
// RFC5424 SD format: [id@org key="val" ...] [id2@org ...]
// This function safely skips past all SD blocks accounting for quoted values.
// Returns the position after the last SD block and space, or 0 if no SD blocks found.
//
// CRITICAL FIX #1: This function was completely missing!
// Without this, SD blocks like [exten@3 action="accept"] remained in event.Message
// causing decoder prematch patterns to fail for CheckPoint and FortiGate logs.
func findSDEnd(s string) int {
	if len(s) == 0 || s[0] != '[' {
		return 0
	}

	i := 0
	for i < len(s) && s[i] == '[' {
		// Find closing ] for this SD block, accounting for quoted values
		inQuote := false
		escaped := false
		j := i + 1

		for j < len(s) {
			if escaped {
				escaped = false
				j++
				continue
			}

			if s[j] == '\\' {
				escaped = true
				j++
				continue
			}

			if s[j] == '"' {
				inQuote = !inQuote
				j++
				continue
			}

			if s[j] == ']' && !inQuote {
				i = j + 1
				// Skip space after SD block
				if i < len(s) && s[i] == ' ' {
					i++
				}
				break
			}

			j++
		}

		// If we didn't find a closing bracket, break
		if j >= len(s) {
			break
		}
	}

	return i
}

func parseRFC5424(s string, event *Event) {
	// RFC5424: TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP [SD-or-NIL] SP MSG
	// Split into at most 6 parts so parts[5] = everything from MSGID onwards (preserves spaces).
	parts := splitN(s, ' ', 6)
	if len(parts) >= 1 {
		if t, err := time.Parse(time.RFC3339Nano, parts[0]); err == nil {
			event.Timestamp = t
		} else if t, err := time.Parse(time.RFC3339, parts[0]); err == nil {
			event.Timestamp = t
		}
	}
	if len(parts) >= 2 && parts[1] != "-" {
		event.Hostname = parts[1]
	}
	if len(parts) >= 3 && parts[2] != "-" {
		event.ProgramName = parts[2]
	}
	// parts[4] = MSGID (often "-"), parts[5] = SD-data + MSG (may contain spaces)
	// We use the remainder (parts[5] onward) as the message body.
	msg := ""
	if len(parts) >= 6 {
		rest := parts[5]

		// CRITICAL FIX #1: Skip RFC5424 Structured Data blocks if present
		// SD blocks like [exten@3 action="accept"] or [meta sequenceId="123"]
		// must be removed before the message is extracted.
		// This fixes CheckPoint and FortiGate RFC5424 variant logs.
		if strings.HasPrefix(rest, "[") {
			sdEnd := findSDEnd(rest)
			if sdEnd > 0 {
				rest = rest[sdEnd:]
				rest = strings.TrimSpace(rest)
			}
		} else if strings.HasPrefix(rest, "- ") {
			// Standard RFC5424: MSGID="-" means NILVALUE, space-separated from MSG
			rest = rest[2:]
		} else if rest == "-" {
			// MSGID="-" with nothing after it
			rest = ""
		}
		msg = rest
	} else if len(parts) >= 5 && parts[4] != "-" {
		msg = parts[4]
	}
	event.Message = strings.TrimSpace(msg)
}

// ─── RFC 3164 ─────────────────────────────────────────────────────────────────

var shortMonths = map[string]bool{
	"Jan": true, "Feb": true, "Mar": true, "Apr": true,
	"May": true, "Jun": true, "Jul": true, "Aug": true,
	"Sep": true, "Oct": true, "Nov": true, "Dec": true,
}

func parseRFC3164(s string, event *Event) bool {
	p := strings.Fields(s)
	// Need at least: Mon DD HH:MM:SS HOST PROG: ...
	if len(p) < 5 || !shortMonths[p[0]] {
		return false
	}
	// p[3] must be a valid hostname:
	// - no '=' (would be a KV field)
	// - no '%' (would be a Cisco mnemonic)
	// - no ':' at end (would be a timestamp like "UTC:")
	// - no '*' or '.' prefix (Cisco clock markers)
	host := p[3]
	if strings.ContainsAny(host, "=%") {
		return false
	}
	if strings.HasSuffix(host, ":") {
		return false
	}
	// p[2] must look like HH:MM:SS (contains colons)
	if !strings.Contains(p[2], ":") {
		return false
	}

	event.Hostname = host
	prog := p[4]
	if idx := strings.IndexByte(prog, '['); idx != -1 {
		prog = prog[:idx]
	}
	event.ProgramName = strings.TrimSuffix(prog, ":")

	// event.Message = log body AFTER stripping "PROG[PID]: " prefix.
	// This is what Wazuh decoders expect: sshd decoders see "Failed password..."
	// not "sshd[1234]: Failed password...".
	// The full "PROG[PID]: MSG" is preserved in event.RawBody for decoders
	// (like CheckPoint) whose prematch expects the complete syslog body.
	fullBody := strings.Join(p[4:], " ")
	// Strip "PROG[PID]: " prefix to get the actual message
	if idx := strings.Index(fullBody, ": "); idx != -1 {
		event.Message = fullBody[idx+2:]
	} else {
		event.Message = fullBody
	}
	return true
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func kvGet(s, key string) string {
	needle := key + "="
	idx := strings.Index(s, needle)
	if idx == -1 {
		return ""
	}
	rest := s[idx+len(needle):]
	if len(rest) == 0 {
		return ""
	}
	if rest[0] == '"' {
		rest = rest[1:]
		if end := strings.IndexByte(rest, '"'); end != -1 {
			return rest[:end]
		}
		return rest
	}
	if end := strings.IndexAny(rest, " \t"); end != -1 {
		return rest[:end]
	}
	return rest
}

func splitN(s string, sep byte, n int) []string {
	var parts []string
	for len(parts) < n-1 {
		idx := strings.IndexByte(s, sep)
		if idx == -1 {
			break
		}
		parts = append(parts, s[:idx])
		s = s[idx+1:]
	}
	if s != "" {
		parts = append(parts, s)
	}
	return parts
}

// parseBareProgMsg handles logs with no syslog envelope but a leading PROG[PID]: prefix.
// Examples:
//   sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2
//   sshd[2404]: Accepted password for root from 192.168.11.1 port 2011 ssh2
//   severity=HIGH facility=AUTH: user=admin action=login
//   level=ERROR module=firewall: connection terminated
//
// Sets ProgramName and Message (stripped of "PROG[PID]: " prefix).
func parseBareProgMsg(s string, event *Event) bool {
	// Reject JSON objects/arrays — these are handled by the json decoder
	if len(s) > 0 && (s[0] == '{' || s[0] == '[') {
		return false
	}

	// Must have ": " separator
	colon := strings.Index(s, ": ")
	if colon <= 0 {
		return false
	}

	progPart := s[:colon] // e.g. "sshd[1234]" or "severity=HIGH facility=AUTH"

	// CRITICAL FIX #2: Allow '=' and spaces in program part for KV-formatted logs
	// Changed from blanket rejection to validation that allows:
	// - "sshd[1234]" (standard)
	// - "severity=HIGH facility=AUTH" (KV format with spaces)
	// - "auth=PAM" (simple KV)
	// Only reject truly problematic characters: newlines, tabs, quotes, braces
	for _, c := range progPart {
		if c == '\n' || c == '\r' || c == '\t' || c == '"' || c == '{' {
			return false
		}
	}

	// Extract program name (the first token before any space or equals)
	var prog string
	firstToken := progPart

	// If there's a space, take the part before the space
	if spaceIdx := strings.IndexByte(progPart, ' '); spaceIdx != -1 {
		firstToken = progPart[:spaceIdx]
	}

	// Remove [pid] suffix if present
	prog = firstToken
	if idx := strings.IndexByte(prog, '['); idx != -1 {
		prog = prog[:idx]
	}

	// If we have "severity=HIGH", extract just "severity"
	if idx := strings.IndexByte(prog, '='); idx != -1 {
		prog = prog[:idx]
	}

	if prog == "" {
		return false
	}

	event.ProgramName = prog
	event.Message = s[colon+2:] // after ": "
	return true
}