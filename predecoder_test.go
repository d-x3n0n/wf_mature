package main

import (
	"testing"
)

// TestParseRFC5424WithStructuredData verifies CRITICAL FIX #1: RFC5424 SD block removal
// Tests that Structured Data blocks are properly removed from RFC5424 messages
func TestParseRFC5424WithStructuredData(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantMsg    string
		wantHost   string
		wantProg   string
		desc       string
	}{
		{
			name:       "CheckPoint CEF with SD",
			input:      `2023-10-15T14:22:30.000Z cp-server CheckPoint - - [exten@3 action="accept"] CEF:0|Check Point|Smart-1|`,
			wantMsg:    `CEF:0|Check Point|Smart-1|`,
			wantHost:   `cp-server`,
			wantProg:   `CheckPoint`,
			desc:       "CheckPoint Smart-1 with [exten@3 ...] SD block removed",
		},
		{
			name:       "FortiGate with SD sequenceId",
			input:      `2023-01-01T12:00:00.123Z FGT60F FortiGate 0 - [meta sequenceId="123"] devname="test" action=block`,
			wantMsg:    `devname="test" action=block`,
			wantHost:   `FGT60F`,
			wantProg:   `FortiGate`,
			desc:       "FortiGate RFC5424 with [meta sequenceId=...] removed",
		},
		{
			name:       "Multiple SD blocks",
			input:      `2023-11-20T10:15:42Z host app 1234 - [id1@1 a="b"][id2@2 c="d"] message text`,
			wantMsg:    `message text`,
			wantHost:   `host`,
			wantProg:   `app`,
			desc:       "Multiple consecutive SD blocks both removed",
		},
		{
			name:       "NIL SD (dash) standard RFC5424",
			input:      `2023-11-20T10:15:42Z host app 1234 - - message only`,
			wantMsg:    `message only`,
			wantHost:   `host`,
			wantProg:   `app`,
			desc:       "Standard RFC5424 with MSGID=- (NIL) and then message",
		},
		{
			name:       "SD with escaped quotes",
			input:      `2023-01-01T00:00:00Z srv1 app - - [id@1 msg="say \"hello\""] actual message`,
			wantMsg:    `actual message`,
			wantHost:   `srv1`,
			wantProg:   `app`,
			desc:       "SD block with escaped quotes inside values",
		},
		{
			name:       "No SD, just message",
			input:      `2023-01-01T00:00:00Z srv2 prog - - This is a plain message`,
			wantMsg:    `This is a plain message`,
			wantHost:   `srv2`,
			wantProg:   `prog`,
			desc:       "RFC5424 without SD block (standard case)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &Event{KVFields: make(map[string]string)}
			parseRFC5424(tt.input, event)

			if event.Message != tt.wantMsg {
				t.Errorf("Message mismatch\n  desc: %s\n  got:  %q\n  want: %q",
					tt.desc, event.Message, tt.wantMsg)
			}
			if event.Hostname != tt.wantHost {
				t.Errorf("Hostname mismatch\n  desc: %s\n  got:  %q\n  want: %q",
					tt.desc, event.Hostname, tt.wantHost)
			}
			if event.ProgramName != tt.wantProg {
				t.Errorf("ProgramName mismatch\n  desc: %s\n  got:  %q\n  want: %q",
					tt.desc, event.ProgramName, tt.wantProg)
			}
		})
	}
}

// TestParseBareProgramMsgWithKVFields verifies CRITICAL FIX #2: Allow spaces and '=' in program part
// Tests that KV-formatted logs are properly parsed
func TestParseBareProgramMsgWithKVFields(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantProg  string
		wantMsg   string
		shouldOk  bool
		desc      string
	}{
		{
			name:     "sshd standard format",
			input:    `sshd[1234]: Failed password for root`,
			wantProg: `sshd`,
			wantMsg:  `Failed password for root`,
			shouldOk: true,
			desc:     "Classic sshd[PID]: message format",
		},
		{
			name:     "severity=HIGH KV format",
			input:    `severity=HIGH facility=AUTH: user=admin action=login`,
			wantProg: `severity`,
			wantMsg:  `user=admin action=login`,
			shouldOk: true,
			desc:     "KV log starting with severity=HIGH before : separator",
		},
		{
			name:     "level=ERROR module=firewall format",
			input:    `level=ERROR module=firewall: connection terminated by timeout`,
			wantProg: `level`,
			wantMsg:  `connection terminated by timeout`,
			shouldOk: true,
			desc:     "Multiple KV fields in program part",
		},
		{
			name:     "sshd with no brackets",
			input:    `sshd: Accepted password for user@192.168.1.1`,
			wantProg: `sshd`,
			wantMsg:  `Accepted password for user@192.168.1.1`,
			shouldOk: true,
			desc:     "sshd without [PID]",
		},
		{
			name:     "auth=PAM: login successful",
			input:    `auth=PAM: login successful`,
			wantProg: `auth`,
			wantMsg:  `login successful`,
			shouldOk: true,
			desc:     "Simple KV format with auth=PAM",
		},
		{
			name:     "JSON array rejection",
			input:    `[{"event": "test"}]: message`,
			wantProg: ``,
			wantMsg:  ``,
			shouldOk: false,
			desc:     "JSON array should be rejected",
		},
		{
			name:     "JSON object rejection",
			input:    `{"key": "value"}: message`,
			wantProg: ``,
			wantMsg:  ``,
			shouldOk: false,
			desc:     "JSON object should be rejected",
		},
		{
			name:     "No colon separator",
			input:    `severity=HIGH facility=AUTH`,
			wantProg: ``,
			wantMsg:  ``,
			shouldOk: false,
			desc:     "No colon: separator should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &Event{KVFields: make(map[string]string)}
			ok := parseBareProgMsg(tt.input, event)

			if ok != tt.shouldOk {
				t.Errorf("OK mismatch\n  desc: %s\n  got:  %v\n  want: %v",
					tt.desc, ok, tt.shouldOk)
				return
			}

			if ok && (event.ProgramName != tt.wantProg || event.Message != tt.wantMsg) {
				if event.ProgramName != tt.wantProg {
					t.Errorf("ProgramName mismatch\n  desc: %s\n  got:  %q\n  want: %q",
						tt.desc, event.ProgramName, tt.wantProg)
				}
				if event.Message != tt.wantMsg {
					t.Errorf("Message mismatch\n  desc: %s\n  got:  %q\n  want: %q",
						tt.desc, event.Message, tt.wantMsg)
				}
			}
		})
	}
}

// TestPreDecodeFullPipeline tests complete Phase 1 with both critical fixes
// Tests the end-to-end PreDecode function with various log formats
func TestPreDecodeFullPipeline(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantMsg   string
		wantHost  string
		wantProg  string
		desc      string
	}{
		{
			name:     "RFC5424 CheckPoint with PRI",
			raw:      `<34>1 2023-10-15T14:22:30Z cp-srv CheckPoint - - [act@3 foo="bar"] CEF:0|CP|`,
			wantMsg:  `CEF:0|CP|`,
			wantHost: `cp-srv`,
			wantProg: `CheckPoint`,
			desc:     "CheckPoint CEF via RFC5424 with PRI + SD",
		},
		{
			name:     "RFC3164 sshd standard",
			raw:      `<34>Mar 21 13:45:32 myhost sshd[1234]: Failed password`,
			wantMsg:  `Failed password`,
			wantHost: `myhost`,
			wantProg: `sshd`,
			desc:     "RFC3164 with sshd",
		},
		{
			name:     "Bare sshd format",
			raw:      `sshd[5678]: Accepted key for user from 10.1.2.3`,
			wantMsg:  `Accepted key for user from 10.1.2.3`,
			wantHost: ``,
			wantProg: `sshd`,
			desc:     "Bare PROG[PID]: MESSAGE",
		},
		{
			name:     "KV format with severity",
			raw:      `severity=ERROR level=critical: system failure detected`,
			wantMsg:  `system failure detected`,
			wantHost: ``,
			wantProg: `severity`,
			desc:     "KV log with severity=ERROR prefix",
		},
		{
			name:     "FortiGate RFC5424 with SD",
			raw:      `<134>1 2023-01-01T12:00:00.123Z FGT60F FortiGate 0 - [meta seq="123"] devname="PNL" action=drop`,
			wantMsg:  `devname="PNL" action=drop`,
			wantHost: `FGT60F`,
			wantProg: `FortiGate`,
			desc:     "FortiGate RFC5424 with SD removal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &Event{
				KVFields: make(map[string]string),
			}
			PreDecode(tt.raw, event)

			if event.Message != tt.wantMsg {
				t.Errorf("Message mismatch\n  desc: %s\n  got:  %q\n  want: %q",
					tt.desc, event.Message, tt.wantMsg)
			}
			if event.Hostname != tt.wantHost {
				t.Errorf("Hostname mismatch\n  desc: %s\n  got:  %q\n  want: %q",
					tt.desc, event.Hostname, tt.wantHost)
			}
			if event.ProgramName != tt.wantProg {
				t.Errorf("ProgramName mismatch\n  desc: %s\n  got:  %q\n  want: %q",
					tt.desc, event.ProgramName, tt.wantProg)
			}
		})
	}
}

// TestFindSDEnd tests the RFC5424 SD parser helper function
// Tests SD block detection and removal logic - no specific byte count assertions
func TestFindSDEnd(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		hasSDEnd bool
		desc     string
	}{
		{
			name:     "Single SD block",
			input:    `[id@1 key="value"] message`,
			hasSDEnd: true,
			desc:     "One SD block followed by space",
		},
		{
			name:     "Multiple SD blocks",
			input:    `[id1@1 a="b"][id2@2 c="d"] msg`,
			hasSDEnd: true,
			desc:     "Two consecutive SD blocks",
		},
		{
			name:     "SD with escaped quotes",
			input:    `[id@1 msg="say \"hello\""] text`,
			hasSDEnd: true,
			desc:     "SD block with escaped quotes",
		},
		{
			name:     "No SD blocks",
			input:    `plain message without SD`,
			hasSDEnd: false,
			desc:     "Plain message without SD",
		},
		{
			name:     "Empty string",
			input:    ``,
			hasSDEnd: false,
			desc:     "Empty input",
		},
		{
			name:     "Dash (NIL value)",
			input:    `- message here`,
			hasSDEnd: false,
			desc:     "Dash (NIL) is not SD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findSDEnd(tt.input)
			hasSD := got > 0
			if hasSD != tt.hasSDEnd {
				t.Errorf("findSDEnd mismatch\n  desc: %s\n  input: %q\n  got:  %d\n  hasSD: %v\n  want hasSD: %v",
					tt.desc, tt.input, got, hasSD, tt.hasSDEnd)
			}
		})
	}
}

// TestStripKVQuotes ensures KV normalization still works
// Tests that quoted values are properly handled
func TestStripKVQuotes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Simple quoted value",
			input: `devname="PNL-FortiGate-60F" action=drop`,
			want:  `devname=PNL-FortiGate-60F action=drop`,
		},
		{
			name:  "Multiple quoted values",
			input: `devname="FGT60F" msg="test message" level="info"`,
			want:  `devname=FGT60F msg=test message level=info`,
		},
		{
			name:  "No quotes",
			input: `devname=FGT60F action=drop`,
			want:  `devname=FGT60F action=drop`,
		},
		{
			name:  "Mixed quotes and no quotes",
			input: `id=123 msg="error text" severity=high`,
			want:  `id=123 msg=error text severity=high`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripKVQuotes(tt.input)
			if got != tt.want {
				t.Errorf("stripKVQuotes mismatch\n  input: %q\n  got:  %q\n  want: %q",
					tt.input, got, tt.want)
			}
		})
	}
}

// TestKVGet ensures kvGet helper still works
// Tests key-value extraction function
func TestKVGet(t *testing.T) {
	tests := []struct {
		name  string
		input string
		key   string
		want  string
	}{
		{
			name:  "Quoted value",
			input: `devname="PNL-FortiGate" action=drop`,
			key:   "devname",
			want:  `PNL-FortiGate`,
		},
		{
			name:  "Unquoted value",
			input: `action=drop reason=timeout`,
			key:   "action",
			want:  `drop`,
		},
		{
			name:  "Key not found",
			input: `action=drop reason=timeout`,
			key:   "missing",
			want:  ``,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := kvGet(tt.input, tt.key)
			if got != tt.want {
				t.Errorf("kvGet mismatch\n  input: %q, key: %q\n  got:  %q\n  want: %q",
					tt.input, tt.key, got, tt.want)
			}
		})
	}
}