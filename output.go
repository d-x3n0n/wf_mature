package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"path/filepath"
	"sync"
	"time"
)

// ─── JSON structures — mirror Wazuh's exact alert/archive output ─────────────

type alertOutput struct {
	Timestamp string            `json:"timestamp"`
	Rule      ruleOutput        `json:"rule"`
	Agent     agentOutput       `json:"agent"`
	Manager   mgr               `json:"manager"`
	ID        string            `json:"id"`
	FullLog   string            `json:"full_log"`
	Decoder   decOutput         `json:"decoder"`
	Data      map[string]string `json:"data,omitempty"`
	Location  string            `json:"location"`
}

type archiveOutput struct {
	Timestamp string            `json:"timestamp"`
	Rule      *ruleOutput       `json:"rule,omitempty"`
	Agent     agentOutput       `json:"agent"`
	Manager   mgr               `json:"manager"`
	ID        string            `json:"id"`
	FullLog   string            `json:"full_log"`
	Decoder   decOutput         `json:"decoder"`
	Data      map[string]string `json:"data,omitempty"`
	Location  string            `json:"location"`
}

type ruleOutput struct {
	Level       int      `json:"level"`
	Description string   `json:"description"`
	ID          string   `json:"id"`
	FiredTimes  int64    `json:"firedtimes"`
	Mail        bool     `json:"mail"`
	Groups      []string `json:"groups,omitempty"`
	GDPR        []string `json:"gdpr,omitempty"`
	GPG13       []string `json:"gpg13,omitempty"`
	HIPAA       []string `json:"hipaa,omitempty"`
	NIST        []string `json:"nist_800_53,omitempty"`
	PCI         []string `json:"pci_dss,omitempty"`
	TSC         []string `json:"tsc,omitempty"`
	MITRE       []string `json:"mitre,omitempty"`
}

type agentOutput struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type mgr struct {
	Name string `json:"name"`
}
type decOutput struct {
	Name string `json:"name"`
}

// ─── Writer ───────────────────────────────────────────────────────────────────

type OutputWriter struct {
	cfg       *Config
	alertMu   sync.Mutex
	archiveMu sync.Mutex
	alertFile *os.File
	archFile  *os.File
}

func NewOutputWriter(c *Config) (*OutputWriter, error) {
	w := &OutputWriter{cfg: c}

	// Ensure parent directory exists for output files
	ensureDir := func(path string) {
		if idx := len(path) - len(filepath.Base(path)) - 1; idx > 0 {
			os.MkdirAll(path[:idx], 0755)
		}
	}

	// Open with user-writable permissions; no root required
	flag := os.O_APPEND | os.O_CREATE | os.O_WRONLY
	var err error
	ensureDir(c.AlertsFile)
	w.alertFile, err = os.OpenFile(c.AlertsFile, flag, 0644)
	if err != nil {
		return nil, fmt.Errorf("cannot open alerts file %q: %w", c.AlertsFile, err)
	}
	ensureDir(c.ArchivesFile)
	w.archFile, err = os.OpenFile(c.ArchivesFile, flag, 0644)
	if err != nil {
		w.alertFile.Close()
		return nil, fmt.Errorf("cannot open archives file %q: %w", c.ArchivesFile, err)
	}

	return w, nil
}

func (w *OutputWriter) Close() {
	if w.alertFile != nil {
		w.alertFile.Close()
	}
	if w.archFile != nil {
		w.archFile.Close()
	}
}

func buildDataMap(event *Event) map[string]string {
	if len(event.KVFields) == 0 && len(event.DynFields) == 0 {
		return nil
	}
	m := make(map[string]string, len(event.KVFields)+len(event.DynFields))
	for k, v := range event.KVFields {
		m[k] = v
	}
	for k, v := range event.DynFields {
		m[k] = v
	}
	if event.SrcIP != "" {
		m["srcip"] = event.SrcIP
	}
	if event.DstIP != "" {
		m["dstip"] = event.DstIP
	}
	if event.SrcUser != "" {
		m["srcuser"] = event.SrcUser
	}
	if event.DstUser != "" {
		m["dstuser"] = event.DstUser
	}
	if event.Action != "" {
		m["action"] = event.Action
	}
	if event.Status != "" {
		m["status"] = event.Status
	}
	if event.SrcPort != "" {
		m["srcport"] = event.SrcPort
	}
	if event.DstPort != "" {
		m["dstport"] = event.DstPort
	}
	return m
}

func makeRuleOutput(r *Rule) ruleOutput {
	return ruleOutput{
		Level:       r.Level,
		Description: r.Description,
		ID:          fmt.Sprintf("%d", r.ID),
		FiredTimes:  r.firedTimes,
		Mail:        false,
		Groups:      r.outputGroups(),
		GDPR:        nilIfEmpty(r.GDPR),
		GPG13:       nilIfEmpty(r.GPG13),
		HIPAA:       nilIfEmpty(r.HIPAA),
		NIST:        nilIfEmpty(r.NIST),
		PCI:         nilIfEmpty(r.PCI),
		TSC:         nilIfEmpty(r.TSC),
		MITRE:       nilIfEmpty(r.MITRE),
	}
}

func (w *OutputWriter) WriteAlert(r *Rule, event *Event) {
	ro := makeRuleOutput(r)
	ro.Description = resolveDesc(ro.Description, event)

	a := alertOutput{
		Timestamp: wazuhTimestamp(event.Timestamp),
		Rule:      ro,
		Agent:     agentOutput{ID: w.cfg.AgentID, Name: w.cfg.AgentName},
		Manager:   mgr{Name: w.cfg.ManagerName},
		ID:        event.EventID,
		FullLog:   event.Message,
		Decoder:   decOutput{Name: event.DecoderFamily},
		Data:      buildDataMap(event),
		Location:  event.Location,
	}
	w.writeLine(&w.alertMu, w.alertFile, &a)
}

// resolveDesc replaces $(field) placeholders with actual event field values.
func resolveDesc(desc string, event *Event) string {
	if !strings.Contains(desc, "$(") {
		return desc
	}
	result := desc
	start := 0
	for {
		i := strings.Index(result[start:], "$(")
		if i == -1 {
			break
		}
		i += start
		j := strings.Index(result[i:], ")")
		if j == -1 {
			break
		}
		j += i
		fieldName := result[i+2 : j]
		value := event.GetField(fieldName)
		if value == "" {
			value = "?"
		}
		result = result[:i] + value + result[j+1:]
		start = i + len(value)
	}
	return result
}

func (w *OutputWriter) WriteArchive(r *Rule, event *Event) {
	a := archiveOutput{
		Timestamp: wazuhTimestamp(event.Timestamp),
		Agent:     agentOutput{ID: w.cfg.AgentID, Name: w.cfg.AgentName},
		Manager:   mgr{Name: w.cfg.ManagerName},
		ID:        event.EventID,
		FullLog:   event.Message,
		Decoder:   decOutput{Name: event.DecoderFamily},
		Data:      buildDataMap(event),
		Location:  event.Location,
	}
	if r != nil {
		ro := makeRuleOutput(r)
		ro.Description = resolveDesc(ro.Description, event)
		a.Rule = &ro
	}
	w.writeLine(&w.archiveMu, w.archFile, &a)
}

func (w *OutputWriter) writeLine(mu *sync.Mutex, f *os.File, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	f.Write(data)
	f.Write([]byte("\n"))
}

func wazuhTimestamp(t time.Time) string {
	return t.Format("2006-01-02T15:04:05.000-0700")
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}