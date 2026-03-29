package main

import (
	"encoding/json"
	"strings"
)

// runJSONDecoder implements the JSON_Decoder plugin referenced in decoder XML.
// It fires when a decoder has PluginDecoder="JSON_Decoder" and its prematch
// matches (i.e. the log starts with a JSON object: ^{\s*" ).
//
// Behaviour mirrors Wazuh's JSON_Decoder:
//  - Parses the full log as a JSON object
//  - Maps well-known field names to event struct fields (srcip, dstip, etc.)
//  - Flattens nested objects using dot notation: user.name, event.action, etc.
//  - All extracted key/value pairs go into event.KVFields (the data block)
//  - Sets event.DecoderFamily and event.DecoderName to "json"
func runJSONDecoder(raw string, event *Event) bool {
	raw = strings.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return false
	}

	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return false
	}

	// Flatten the JSON into dot-notation key/value pairs
	fields := make(map[string]string)
	flattenJSON("", obj, fields)

	// Map all fields into event
	for k, v := range fields {
		event.SetNamedField(k, v)
		// Also try well-known aliases → canonical field names
		if canonical, ok := jsonFieldAlias(k); ok {
			event.SetNamedField(canonical, v)
		}
	}

	event.DecoderFamily = "json"
	event.DecoderName   = "json"
	return true
}

// flattenJSON recursively flattens a JSON object into dot-notation string fields.
// {"user":{"name":"root","id":0}} → {"user.name":"root","user.id":"0"}
func flattenJSON(prefix string, obj map[string]interface{}, out map[string]string) {
	for k, v := range obj {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch val := v.(type) {
		case map[string]interface{}:
			flattenJSON(key, val, out)
		case []interface{}:
			// Arrays: store first element and indexed elements
			for i, elem := range val {
				switch ev := elem.(type) {
				case map[string]interface{}:
					flattenJSON(key, ev, out)
				case string:
					if i == 0 {
						out[key] = ev
					}
				}
			}
		case string:
			out[key] = val
		case float64:
			// JSON numbers — convert to string
			if val == float64(int64(val)) {
				out[key] = strings.TrimRight(strings.TrimRight(
					strings.Replace(
						strings.Replace(string(mustMarshal(val)), ".000000", "", 1),
						"e+", "e", 1),
					"0"), ".")
				// Simpler: just format as integer if it's whole
				out[key] = formatNumber(val)
			} else {
				out[key] = formatNumber(val)
			}
		case bool:
			if val {
				out[key] = "true"
			} else {
				out[key] = "false"
			}
		case nil:
			// skip null values
		}
	}
}

func formatNumber(f float64) string {
	if f == float64(int64(f)) {
		b, _ := json.Marshal(int64(f))
		return string(b)
	}
	b, _ := json.Marshal(f)
	return string(b)
}

func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

// jsonFieldAlias maps common JSON field name variants to Wazuh canonical names.
// This lets rules using <field name="srcip"> work regardless of whether the
// JSON uses "srcip", "src_ip", "source", "sourceIPAddress", etc.
func jsonFieldAlias(key string) (string, bool) {
	// Normalise: lowercase for matching
	lk := strings.ToLower(key)
	switch lk {
	// Source IP
	case "src_ip", "source", "sourceip", "sourceipaddress",
		"client_ip", "clientip", "client.ip",
		"ipaddr", "ip_address", "remoteaddr", "remote_addr",
		"source.ip", "source.address", "src.ip",
		"network.src_ip", "observer.ip",
		"src", "saddr":
		return "srcip", true

	// Destination IP
	case "dst_ip", "dest_ip", "destination", "destinationip",
		"destinationipaddress", "server_ip", "serverip",
		"destination.ip", "destination.address", "dst.ip",
		"network.dst_ip",
		"dst", "daddr":
		return "dstip", true

	// Source port
	case "src_port", "source_port", "sport", "spt",
		"source.port", "src.port", "client.port":
		return "srcport", true

	// Destination port
	case "dst_port", "dest_port", "dport", "dpt",
		"destination.port", "dst.port", "server.port":
		return "dstport", true

	// User
	case "username", "user_name", "user", "login", "account",
		"actor", "initiator", "subjectusername",
		"user.name", "user.email", "user.id",
		"actor.user", "source.user", "client.user":
		return "srcuser", true

	// Action / event type
	case "event_type", "eventtype", "event_name", "eventname",
		"type", "category", "operation",
		"event.action", "event.category", "event.type",
		"event_action":
		return "action", true

	// Status / result
	case "result", "outcome", "event_outcome", "response",
		"event.outcome", "status_code", "http.response.status_code":
		return "status", true

	// Protocol
	case "proto", "network_transport", "transport":
		return "protocol", true

	// URL
	case "uri", "path", "request_uri", "url_path", "http_url":
		return "url", true

	// ID / message ID
	case "event_id", "eventid", "log_id", "logid", "message_id":
		return "id", true
	}
	return "", false
}
