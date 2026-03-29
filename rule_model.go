package main

import (
	"regexp"
	"strings"
)

// ─── RulePattern ─────────────────────────────────────────────────────────────

// RulePattern is a compiled match/regex condition. nil always passes.
type RulePattern struct {
	re     *regexp.Regexp
	negate bool
}

// newLiteralPattern compiles a <match> tag (case-insensitive substring match).
func newLiteralPattern(s string) (*RulePattern, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	negate := strings.HasPrefix(s, "!")
	if negate {
		s = s[1:]
	}
	re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(s))
	if err != nil {
		return nil, err
	}
	return &RulePattern{re: re, negate: negate}, nil
}

// newRegexPattern compiles a <regex> tag (case-insensitive regex match).
func newRegexPattern(s string) (*RulePattern, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	negate := strings.HasPrefix(s, "!")
	if negate {
		s = s[1:]
	}
	// Wrap in non-capturing group when | is present so anchors apply to whole pattern.
	// e.g. "012a0002|012a0003" → "(?:012a0002|012a0003)" so ^...$ works correctly.
	pat := s
	if strings.Contains(pat, "|") && !strings.HasPrefix(pat, "(?") {
		pat = "(?:" + pat + ")"
	}
	re, err := regexp.Compile("(?i)" + pat)
	if err != nil {
		return nil, err
	}
	return &RulePattern{re: re, negate: negate}, nil
}

func (p *RulePattern) MatchString(s string) bool {
	if p == nil {
		return true // nil pattern = no condition = always passes
	}
	matched := p.re.MatchString(s)
	if p.negate {
		return !matched
	}
	return matched
}

// ─── FieldRule ────────────────────────────────────────────────────────────────

// FieldRule is a <field name="x">pattern</field> condition.
type FieldRule struct {
	Name    string
	Pattern *RulePattern
}

// ─── Rule ─────────────────────────────────────────────────────────────────────

// Rule is a fully compiled Wazuh/OSSEC rule. Mirrors RuleInfo.
type Rule struct {
	ID          int
	Level       int
	Frequency   int
	Timeframe   int
	NoAlert     bool // noalert="1" — fires for chaining but never writes alert output
	IgnoreSecs  int  // ignore="N" — suppress repeated alerts for N seconds

	Description  string
	DecodedAs    string
	FileGroup    string // group name from <group name="..."> XML attribute
	GroupRaw     string // raw content of <group> element
	ParsedGroups []string

	// Compliance tags — parsed from GroupRaw, displayed in alert output.
	// Values use the exact format Wazuh uses: dots, not underscores.
	// e.g. PCI=["10.2.4","10.2.5"] GDPR=["IV_32.2","IV_35.7.d"]
	PCI   []string
	GDPR  []string
	HIPAA []string
	NIST  []string
	GPG13 []string
	TSC   []string
	MITRE []string // from both <mitre><id> and group tags

	IfSIDs        []int
	IfMatchedSIDs []int
	SameSourceIP  bool

	// Conditions — nil means "no condition" (always passes)
	Match       *RulePattern
	Regex       *RulePattern
	SrcIPPat    *RulePattern
	DstIPPat    *RulePattern
	UserPat     *RulePattern
	StatusPat   *RulePattern
	ActionPat   *RulePattern
	URLPat      *RulePattern
	ProtocolPat *RulePattern
	FieldRules  []FieldRule

	// Wazuh's firedtimes counter — incremented on each alert
	firedTimes int64
}

func (r *Rule) incrFired() int64 {
	r.firedTimes++
	return r.firedTimes
}

// outputGroups returns the clean group list for alert JSON output.
// Matches Wazuh exactly: file-level groups first, then rule-level groups.
// Compliance tags are NOT included here (they go in separate top-level fields).
// Trailing commas and empty entries are stripped.
func (r *Rule) outputGroups() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		// Skip compliance tag groups — they go in separate output fields.
		lower := strings.ToLower(s)
		if strings.HasPrefix(lower, "pci_dss_") ||
			strings.HasPrefix(lower, "gdpr_") ||
			strings.HasPrefix(lower, "hipaa_") ||
			strings.HasPrefix(lower, "nist_800_53_") ||
			strings.HasPrefix(lower, "gpg13_") ||
			strings.HasPrefix(lower, "tsc_") {
			return
		}
		if seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, g := range strings.Split(r.FileGroup, ",") {
		add(g)
	}
	for _, g := range r.ParsedGroups {
		add(g)
	}
	return out
}

func hasSIDInList(sid int, list []int) bool {
	for _, s := range list {
		if s == sid {
			return true
		}
	}
	return false
}
