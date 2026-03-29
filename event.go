package main

import (
	"sync/atomic"
	"time"
)

var globalSeq uint64

func nextSeq() uint64 { return atomic.AddUint64(&globalSeq, 1) }

// Event carries one log line through the entire pipeline.
// Mirrors Wazuh's Eventinfo struct.
type Event struct {
	Raw      string
	RawBody  string // body after PRI strip, before RFC5424/3164 envelope removal
	Location string

	// Phase 1 — envelope
	Timestamp   time.Time
	Hostname    string
	ProgramName string
	Message       string
	// NormalMessage is Message with quoted KV values stripped (used by decoders)
	NormalMessage string

	// Phase 2 — decoder
	DecoderName   string // most-specific child decoder
	DecoderFamily string // root decoder name (used in output JSON)

	// Named decoded fields (standard Wazuh order[] targets)
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
	SrcUser  string
	DstUser  string
	Protocol string
	Action   string
	Status   string
	URL      string
	ID       string
	Data     string
	Extra    string // extra_data

	// ALL key=value pairs from the raw log body → goes into "data" block
	KVFields map[string]string

	// Dynamic / overflow decoder fields
	DynFields map[string]string

	// Phase 3 — matched rule SIDs (accumulate during evaluation)
	MatchedSIDs []int

	// Wazuh-format event ID: "unixsec.sequence"
	EventID string
}

func NewEvent(raw, location string) *Event {
	ts := time.Now()
	seq := nextSeq()
	return &Event{
		Raw:       raw,
		Location:  location,
		Timestamp: ts,
		KVFields:  make(map[string]string),
		DynFields: make(map[string]string),
		EventID:   formatEventID(ts, seq),
	}
}

func formatEventID(t time.Time, seq uint64) string {
	return uitoa(uint64(t.Unix())) + "." + uitoa(seq)
}

// SetNamedField routes a captured decoder value to the correct struct field.
// Also stores in KVFields so it appears in the "data" output block.
// Mirrors Wazuh's order[] function pointers (SrcIP_FP, SrcUser_FP, etc.)
// Strips surrounding double-quotes from captured values so that FOS6/7 logs
// (which quote all field values) produce clean decoded fields.
func (e *Event) SetNamedField(name, value string) {
	value = stripFieldQuotes(value)
	e.KVFields[name] = value
	switch name {
	case "srcip", "audit.srcip":
		e.SrcIP = value
	case "dstip", "audit.dstip":
		e.DstIP = value
	case "srcport":
		e.SrcPort = value
	case "dstport":
		e.DstPort = value
	case "srcuser", "user":
		e.SrcUser = value
	case "dstuser":
		e.DstUser = value
	case "protocol":
		e.Protocol = value
	case "action":
		e.Action = value
	case "status":
		e.Status = value
	case "url":
		e.URL = value
	case "id":
		e.ID = value
	case "data":
		e.Data = value
	case "extra_data":
		e.Extra = value
	default:
		e.DynFields[name] = value
	}
}

// GetField returns any field by name: named, dynamic, or raw KV.
func (e *Event) GetField(name string) string {
	switch name {
	case "srcip":
		return e.SrcIP
	case "dstip":
		return e.DstIP
	case "srcport":
		return e.SrcPort
	case "dstport":
		return e.DstPort
	case "srcuser", "user":
		return e.SrcUser
	case "dstuser":
		return e.DstUser
	case "protocol":
		return e.Protocol
	case "action":
		return e.Action
	case "status":
		return e.Status
	case "url":
		return e.URL
	case "id":
		return e.ID
	case "data":
		return e.Data
	case "extra_data":
		return e.Extra
	}
	if v, ok := e.DynFields[name]; ok {
		return v
	}
	return e.KVFields[name]
}

func uitoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 20)
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// stripFieldQuotes removes surrounding double-quotes from a decoded field value.
// FOS6/7 quotes all values: action="login" → captured as "login" → strip → login
// FOS5 does not quote: action=login → captured as login → unchanged
func stripFieldQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	// Handle partial: trailing " from \S+ consuming closing quote
	if len(s) > 0 && s[len(s)-1] == '"' {
		return s[:len(s)-1]
	}
	return s
}
