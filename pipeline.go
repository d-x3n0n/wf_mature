package main

import (
	"fmt"
	"log"
	"strings"
)

// Config holds all runtime configuration.
type Config struct {
	AgentID      string
	AgentName    string
	ManagerName  string
	AlertsFile   string
	ArchivesFile string
	Port         int    // UDP port
	TCPPort      int    // TCP port (0 = disabled)
	DecoderFiles []string
	RuleFiles    []string
	TestLog      string // set from config file "test = ..." or -test flag
}

func DefaultConfig() *Config {
	return &Config{
		AgentID:      "000",
		AgentName:    "watchflux",
		ManagerName:  "watchflux",
		AlertsFile:   "alerts.json",
		ArchivesFile: "archives.json",
		Port:         514,
		TCPPort:      0,
	}
}

// Pipeline is the fully initialised engine.
type Pipeline struct {
	roots  []*DecoderNode
	rules  []*Rule
	writer *OutputWriter
	cfg    *Config
}

func NewPipeline(c *Config) (*Pipeline, error) {
	writer, err := NewOutputWriter(c)
	if err != nil {
		return nil, err
	}
	p := &Pipeline{cfg: c, writer: writer}

	var allDecoders []*Decoder
	for _, f := range c.DecoderFiles {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		ds, err := ParseDecoderFile(f)
		if err != nil {
			return nil, fmt.Errorf("decoders %s: %w", f, err)
		}
		log.Printf("[init] decoder file %-50s → %d decoders", f, len(ds))
		allDecoders = append(allDecoders, ds...)
	}
	p.roots = BuildDecoderTree(allDecoders)
	log.Printf("[init] decoder tree: %d root(s), %d total", len(p.roots), len(allDecoders))

	for _, f := range c.RuleFiles {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		rs, err := ParseRuleFile(f)
		if err != nil {
			return nil, fmt.Errorf("rules %s: %w", f, err)
		}
		log.Printf("[init] rule file    %-50s → %d rules", f, len(rs))
		p.rules = append(p.rules, rs...)
	}
	log.Printf("[init] total rules: %d", len(p.rules))

	return p, nil
}

func (p *Pipeline) Close() {
	p.writer.Close()
}

// Process runs one raw log line through the full 3-phase pipeline.
// Returns the event and any rules that matched at alert level.
func (p *Pipeline) Process(raw, location string) (*Event, []*Rule) {
	event := NewEvent(raw, location)

	// Phase 1: PreDecode
	PreDecode(raw, event)

	// Phase 2: Decode
	RunDecoders(p.roots, event)

	// Phase 3: Evaluate rules
	// EvaluateRules takes (event, rules) and returns matched rules
	allMatched := EvaluateRules(event, p.rules)

	// Collect alert rules (level > 0) and increment their counters first,
	// so both alerts.json and archives.json get the same firedtimes value.
	var alertRules []*Rule
	for _, r := range allMatched {
		// NoAlert rules fire for if_sid chaining but never produce alert output
		if r.Level > 0 && !r.NoAlert {
			r.incrFired()
			alertRules = append(alertRules, r)
		}
	}

	// Find highest-level rule for the archive entry
	var bestRule *Rule
	for _, r := range alertRules {
		if bestRule == nil || r.Level > bestRule.Level {
			bestRule = r
		}
	}

	// Write outputs
	p.writer.WriteArchive(bestRule, event)
	for _, r := range alertRules {
		p.writer.WriteAlert(r, event)
	}

	return event, alertRules
}