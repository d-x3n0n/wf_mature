package main

import (
	"encoding/xml"
	"regexp"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ─── Decoder XML loader ───────────────────────────────────────────────────────

type xmlDecoderFile struct {
	Decoders []xmlDecoder `xml:"decoder"`
}

type xmlDecoder struct {
	Name         string       `xml:"name,attr"`
	Parent       string       `xml:"parent"`
	ProgName     xmlProgName  `xml:"program_name"`
	PluginDecoder string      `xml:"plugin_decoder"`
	Fts          string       `xml:"fts"`          // ignored — FTS not implemented
	FtsComment   string       `xml:"ftscomment"`   // ignored
	Prematches  []xmlTextOff  `xml:"prematch"`
	Regexes     []xmlTextOff  `xml:"regex"`
	Order        string       `xml:"order"`
	Type         string       `xml:"type"`
}

type xmlProgName struct {
	Present bool
	Value   string
}

func (p *xmlProgName) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.Present = true
	return d.DecodeElement(&p.Value, &start)
}

type xmlTextOff struct {
	Offset string `xml:"offset,attr"`
	Type   string `xml:"type,attr"`
	Value  string `xml:",chardata"`
}

// ParseDecoderFile reads one XML decoder file → flat []*Decoder.
func ParseDecoderFile(path string) ([]*Decoder, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// Pre-sanitize XML: replace \< (OSSEC literal angle-bracket escape) with &lt;
	// so Go's strict XML parser doesn't choke on bare < inside element content.
	sanitized := sanitizeDecoderXML(string(data))

	var file xmlDecoderFile
	if err := xml.Unmarshal([]byte("<root>"+sanitized+"</root>"), &file); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var out []*Decoder
	for idx, xd := range file.Decoders {
		d := &Decoder{
			Name:          strings.TrimSpace(xd.Name),
			Parent:        strings.TrimSpace(xd.Parent),
			ProgName:      xd.ProgName.Value,
			HasProgName:   xd.ProgName.Present,
			PluginDecoder: strings.TrimSpace(xd.PluginDecoder),
		}

		// Multiple <prematch> tags = OR logic.
		// Each tag may itself end with | indicating more OR alternatives follow.
		// We combine all into a single compiled OR pattern.
		var pmPatterns []string
		pmIsPCRE2 := false
		for _, xpm := range xd.Prematches {
			pm := strings.TrimSpace(xpm.Value)
			if pm == "" {
				continue
			}
			// Strip trailing | (it's the XML multi-prematch OR separator)
			pm = strings.TrimSuffix(pm, "|")
			pm = strings.TrimSpace(pm)
			if pm != "" {
				pmPatterns = append(pmPatterns, pm)
			}
			if strings.ToLower(xpm.Type) == "pcre2" {
				pmIsPCRE2 = true
			}
			// Store offset from first prematch (they should all be same)
			if d.PrematchOffset == OffsetFull {
				d.PrematchOffset = parseOffset(xpm.Offset)
			}
		}
		if len(pmPatterns) > 0 {
			combined := strings.Join(pmPatterns, "|")
			var re *regexp.Regexp
			var err error
			if pmIsPCRE2 {
				// PCRE2: compile as native Go regex (no OSSEC translation)
				re, err = regexp.Compile("(?i)" + combined)
			} else {
				re, err = compilePrematch(combined)
			}
			if err != nil {
				return nil, fmt.Errorf("decoder[%d] %q prematch %q: %w", idx, d.Name, combined, err)
			}
			d.Prematch = re
		}

		// Multiple <regex> tags = OR logic (same as prematch).
		var rxPatterns []string
		rxIsPCRE2 := false
		for _, xrx := range xd.Regexes {
			rx := strings.TrimSpace(xrx.Value)
			if rx == "" {
				continue
			}
			rx = strings.TrimSuffix(rx, "|")
			rx = strings.TrimSpace(rx)
			if rx != "" {
				rxPatterns = append(rxPatterns, rx)
			}
			if strings.ToLower(xrx.Type) == "pcre2" {
				rxIsPCRE2 = true
			}
			if d.RegexOffset == OffsetFull {
				d.RegexOffset = parseOffset(xrx.Offset)
			}
		}
		if len(rxPatterns) > 0 {
			// Strip OSSEC fallback alternatives like |(\.*)$ or |(\.*)
			// These are PCRE no-op fallbacks that cause Go RE2 to match entire strings.
			for i, p := range rxPatterns {
				rxPatterns[i] = stripOSSECFallback(p)
			}
			combined := strings.Join(rxPatterns, "|")
			var re *regexp.Regexp
			var err error
			if rxIsPCRE2 {
				// PCRE2: compile as native Go regex (no OSSEC translation, no flex)
				re, err = regexp.Compile("(?i)" + combined)
				if err != nil {
					return nil, fmt.Errorf("decoder[%d] %q regex(pcre2) %q: %w", idx, d.Name, combined, err)
				}
				d.Regex = re
				// Also store in RegexFlex for consistency (same pattern)
				d.RegexFlex = re
			} else {
				re, err = compileRegex(combined)
				if err != nil {
					return nil, fmt.Errorf("decoder[%d] %q regex %q: %w", idx, d.Name, combined, err)
				}
				d.Regex = re
				reFlex, ferr := compileRegexFlex(combined)
				if ferr == nil {
					d.RegexFlex = reFlex
				}
			}
		}

		for _, p := range strings.Split(xd.Order, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				d.Order = append(d.Order, p)
			}
		}

		// Compile program_name regex if a non-empty value was given
		if d.HasProgName && d.ProgName != "" {
			re, err := regexp.Compile("(?i)" + d.ProgName)
			if err != nil {
				return nil, fmt.Errorf("decoder[%d] %q program_name %q: %w", idx, d.Name, d.ProgName, err)
			}
			d.ProgNameRe = re
		}

		out = append(out, d)
	}

	markGetNext(out)
	return out, nil
}

func markGetNext(decoders []*Decoder) {
	type key struct{ name, parent string }
	seen := map[key][]int{}
	for i, d := range decoders {
		k := key{d.Name, d.Parent}
		seen[k] = append(seen[k], i)
	}
	for _, indices := range seen {
		for _, i := range indices[:len(indices)-1] {
			decoders[i].GetNext = true
		}
	}
}

func parseOffset(s string) OffsetType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "after_parent":
		return OffsetAfterParent
	case "after_prematch":
		return OffsetAfterPrematch
	case "after_regex":
		return OffsetAfterRegex
	default:
		return OffsetFull
	}
}

// ─── Rule XML loader ──────────────────────────────────────────────────────────

type xmlRuleFile struct {
	Groups []xmlGroup `xml:"group"`
}
type xmlGroup struct {
	Name  string    `xml:"name,attr"`
	Rules []xmlRule `xml:"rule"`
}
type xmlRule struct {
	ID        int    `xml:"id,attr"`
	Level     int    `xml:"level,attr"`
	Frequency int    `xml:"frequency,attr"`
	Timeframe int    `xml:"timeframe,attr"`
	NoAlert   int    `xml:"noalert,attr"`
	Ignore    int    `xml:"ignore,attr"`

	DecodedAs    string `xml:"decoded_as"`
	IfSID        string `xml:"if_sid"`
	IfMatchedSID string `xml:"if_matched_sid"`
	SameSourceIP string `xml:"same_source_ip"`

	Match    string `xml:"match"`
	Regex    string `xml:"regex"`
	SrcIP    string `xml:"srcip"`
	DstIP    string `xml:"dstip"`
	User     string `xml:"user"`
	Status   string `xml:"status"`
	Action   string `xml:"action"`
	URL      string `xml:"url"`
	Protocol string `xml:"protocol"`

	Fields      []xmlField `xml:"field"`
	Description string     `xml:"description"`
	Group       string     `xml:"group"`
	Mitre       xmlMitre   `xml:"mitre"`
	Info        []xmlInfo  `xml:"info"`          // ignored — informational only
}
type xmlField struct {
	Name    string `xml:"name,attr"`
	Type    string `xml:"type,attr"`
	Pattern string `xml:",chardata"`
}
type xmlMitre struct {
	IDs []string `xml:"id"`
}

func ParseRuleFile(path string) ([]*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var file xmlRuleFile
	if err := xml.Unmarshal([]byte("<rulefile>"+string(data)+"</rulefile>"), &file); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var out []*Rule
	for _, grp := range file.Groups {
		for _, xr := range grp.Rules {
			r, err := buildRule(xr, grp.Name)
			if err != nil {
				return nil, fmt.Errorf("rule %d: %w", xr.ID, err)
			}
			out = append(out, r)
		}
	}
	return out, nil
}

func buildRule(xr xmlRule, fileGroup string) (*Rule, error) {
	r := &Rule{
		ID:           xr.ID,
		Level:        xr.Level,
		Frequency:    xr.Frequency,
		Timeframe:    xr.Timeframe,
		NoAlert:      xr.NoAlert != 0,
		IgnoreSecs:   xr.Ignore,
		Description:  strings.TrimSpace(xr.Description),
		FileGroup:    fileGroup,
		GroupRaw:     strings.TrimSpace(xr.Group),
		DecodedAs:    strings.TrimSpace(xr.DecodedAs),
		SameSourceIP: strings.TrimSpace(xr.SameSourceIP) != "",
		MITRE:        xr.Mitre.IDs,
	}

	for _, g := range strings.Split(xr.Group, ",") {
		g = strings.TrimSpace(g)
		if g != "" {
			r.ParsedGroups = append(r.ParsedGroups, g)
		}
	}

	r.PCI   = extractCompliance(r.GroupRaw, "pci_dss_")
	r.GDPR  = extractCompliance(r.GroupRaw, "gdpr_")
	r.HIPAA = extractCompliance(r.GroupRaw, "hipaa_")
	r.NIST  = extractCompliance(r.GroupRaw, "nist_800_53_")
	r.GPG13 = extractCompliance(r.GroupRaw, "gpg13_")
	r.TSC   = extractCompliance(r.GroupRaw, "tsc_")

	var err error
	if r.IfSIDs, err = parseSIDList(xr.IfSID); err != nil {
		return nil, err
	}
	if r.IfMatchedSIDs, err = parseSIDList(xr.IfMatchedSID); err != nil {
		return nil, err
	}

	if r.Match, err = newRegexPattern(xr.Match); err != nil {  // ^ and | supported in match
		return nil, fmt.Errorf("match: %w", err)
	}
	if r.Regex, err = newRegexPattern(xr.Regex); err != nil {
		return nil, fmt.Errorf("regex: %w", err)
	}
	if r.SrcIPPat, err = newRegexPattern(xr.SrcIP); err != nil {
		return nil, err
	}
	if r.DstIPPat, err = newRegexPattern(xr.DstIP); err != nil {
		return nil, err
	}
	if r.UserPat, err = newRegexPattern(xr.User); err != nil {
		return nil, err
	}
	if r.StatusPat, err = newRegexPattern(xr.Status); err != nil {
		return nil, err
	}
	if r.ActionPat, err = newRegexPattern(xr.Action); err != nil {
		return nil, err
	}
	if r.URLPat, err = newRegexPattern(xr.URL); err != nil {
		return nil, err
	}
	if r.ProtocolPat, err = newRegexPattern(xr.Protocol); err != nil {
		return nil, err
	}

	for _, xf := range xr.Fields {
		pat := strings.TrimSpace(xf.Pattern)
		if pat == "" {
			continue
		}
				var p *RulePattern
		var err error
		if strings.ToLower(xf.Type) == "pcre2" {
			// PCRE2 field pattern — compile as native Go regex
			// Go RE2 doesn't support lookaheads; skip patterns that use them
			if strings.Contains(pat, "(?!") || strings.Contains(pat, "(?=") ||
			   strings.Contains(pat, "(?<") {
				// Lookahead/lookbehind: skip (always passes)
				continue
			}
			p, err = newRegexPattern(pat)
		} else {
			p, err = newRegexPattern(pat)
		}
		if err != nil {
			return nil, fmt.Errorf("field %q pattern %q: %w", xf.Name, pat, err)
		}
		if p != nil {
			r.FieldRules = append(r.FieldRules, FieldRule{
				Name: strings.TrimSpace(xf.Name), Pattern: p,
			})
		}
	}

	return r, nil
}

func extractCompliance(groupStr, prefix string) []string {
	var out []string
	lp := strings.ToLower(prefix)
	for _, g := range strings.Split(groupStr, ",") {
		g = strings.TrimSpace(g)
		if len(g) >= len(lp) && strings.ToLower(g[:len(lp)]) == lp {
			val := g[len(prefix):]
			if val != "" {
				out = append(out, val)
			}
		}
	}
	return out
}

func parseSIDList(s string) ([]int, error) {
	var ids []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid SID %q: %w", part, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// sanitizeDecoderXML fixes common XML validity issues in Wazuh decoder files:
//   \< → &lt;   (OSSEC regex escape for literal <, invalid in XML content)
//   \> → &gt;   (similar, for literal >)
// These appear in <prematch> patterns like ^\<\d+> (syslog PRI matching).
func sanitizeDecoderXML(s string) string {
	s = strings.ReplaceAll(s, `\<`, `&lt;`)
	s = strings.ReplaceAll(s, `\>`, `&gt;`)
	return s
}

// stripOSSECFallback removes trailing |(\.*)$ and |(.*) fallback alternatives
// from OSSEC regex patterns. These are PCRE no-op fallbacks used in Wazuh decoders
// (e.g. action:"(\.*)";|(\.*)$) that cause Go RE2 to incorrectly match entire lines.
func stripOSSECFallback(s string) string {
	// Remove patterns ending with |(...fallback...)
	// Common forms: |(\.*)$  |(\.*)  |(.*)$  |(.*)
	for _, suffix := range []string{`|(\.*)$`, `|(\.*)`} {
		if strings.HasSuffix(s, suffix) {
			s = s[:len(s)-len(suffix)]
		}
	}
	return strings.TrimSpace(s)
}

// xmlInfo represents <info type="cve">...</info> — parsed but not used.
type xmlInfo struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}
