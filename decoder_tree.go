package main

import "strings"

// BuildDecoderTree builds the parent→child decoder tree from a flat list.
//
// KEY DESIGN: Multiple decoders sharing the same name (like the many cisco-ios
// root variants) all share one canonical Children list. When any variant fires,
// its children are available. We achieve this by:
//   1. Building a canonical node per unique name (first occurrence)
//   2. Attaching ALL same-named root decoders as variants on that canonical node
//   3. Children are attached to the canonical node, not individual variants
func BuildDecoderTree(decoders []*Decoder) []*DecoderNode {
	// canonical maps decoder name → the one representative node that holds children
	canonical := map[string]*DecoderNode{}
	// allNodes holds every decoder node in order
	allNodes := make([]*DecoderNode, len(decoders))
	for i, d := range decoders {
		allNodes[i] = &DecoderNode{Decoder: d}
		if _, exists := canonical[d.Name]; !exists {
			canonical[d.Name] = allNodes[i]
		}
	}

	// Attach children to their canonical parent node
	// Build the list of root nodes (those with no parent)
	var roots []*DecoderNode
	for _, n := range allNodes {
		p := strings.TrimSpace(n.Decoder.Parent)
		if p == "" {
			// Root decoder — group same-named roots as variants on the canonical node
			canon := canonical[n.Decoder.Name]
			if n != canon {
				// This is an additional variant of the same root decoder name
				// Add it as a Variant so RunDecoders can try all variants
				canon.Variants = append(canon.Variants, n)
			} else {
				roots = append(roots, n)
			}
			continue
		}
		// Child decoder — attach to canonical parent
		if pn := canonical[p]; pn != nil {
			pn.Children = append(pn.Children, n)
		} else {
			// Orphan — treat as root
			roots = append(roots, n)
		}
	}

	return roots
}

// RunDecoders runs the decoder tree against one event.
// First tries event.Message (envelope-stripped body — standard for most decoders).
// If nothing matches and RawBody differs (e.g. RFC5424 was stripped), tries RawBody.
// This handles decoders like CheckPoint Smart-1 whose prematch expects the full
// "1 TIMESTAMP HOSTNAME PROG PID - [..." line, not just the stripped message.
func RunDecoders(roots []*DecoderNode, event *Event) {
	log := event.Message
	for _, root := range roots {
		if tryRootFamily(root, event, log) {
			return
		}
	}
	// Fallback: try RawBody when it differs from Message (RFC5424/3164 was stripped)
	if event.RawBody != "" && event.RawBody != event.Message {
		for _, root := range roots {
			if tryRootFamily(root, event, event.RawBody) {
				return
			}
		}
	}
}

// tryRootFamily tries a root decoder AND all its same-named variants.
// Children are always taken from the canonical node (shared across all variants).
func tryRootFamily(node *DecoderNode, event *Event, log string) bool {
	// node IS the canonical node (first with this name, has all children)
	if tryRoot(node, node, event, log) {
		return true
	}
	// Try additional variants — pass canonical node for children lookup
	for _, v := range node.Variants {
		if tryRoot(v, node, event, log) {
			return true
		}
	}
	return false
}

// tryRoot attempts one decoder node.
// canonical is the node that owns the Children list (may differ from node when
// node is a variant — all same-named root decoders share the canonical's children).
func tryRoot(node, canonical *DecoderNode, event *Event, log string) bool {
	d := node.Decoder

	if !matchProgName(d, event.ProgramName) {
		return false
	}

	// Handle plugin decoders
	if d.PluginDecoder != "" {
		switch strings.ToUpper(d.PluginDecoder) {
		case "JSON_DECODER":
			// Check prematch first (^{\s*")
			if d.Prematch != nil && !d.Prematch.MatchString(log) {
				return false
			}
			if !runJSONDecoder(log, event) {
				return false
			}
			setDecoderNames(event, d)
			return true
		default:
			// Unknown plugin — fall through to normal prematch/regex handling
		}
	}

	pmEnd, _, ok := applyPrematchWithStart(d, log, log, "", "")
	if !ok {
		return false
	}

	regEnd := ""
	if d.Regex != nil || d.RegexFlex != nil {
		src := pickSlice(d.RegexOffset, log, log, pmEnd, "")
		m, after, ok := runRegex(d, src)
		if !ok {
			return false
		}
		applyOrderWithOffset(d, event, m)
		regEnd = after
	}

	setDecoderNames(event, d)

	// Always use canonical's children — they are shared across all same-named variants
	if len(canonical.Children) > 0 {
		// Pass pmEnd (after root prematch end) as parentSlice so that child
		// decoders with offset="after_parent" see the slice AFTER the root's
		// prematch, not from its match start. This matches Wazuh semantics:
		// e.g. auditd root "^type=" → children see "SYSCALL msg=..." not "type=SYSCALL..."
		parentSlice := pmEnd
		if parentSlice == "" {
			parentSlice = log // no prematch on root → full log
		}
		runChildren(canonical.Children, event, log, parentSlice, regEnd)
	}
	return true
}

// runChildren walks child decoders with Wazuh GetNext chain semantics.
func runChildren(children []*DecoderNode, event *Event,
	fullLog, parentEnd, initialPrevRegex string) {

	prevRegex := initialPrevRegex
	i := 0
	for i < len(children) {
		child := children[i]
		d := child.Decoder
		chainName := d.Name

		pmEnd, parentStart, pmOK := applyPrematchWithStart(d, fullLog, parentEnd, "", prevRegex)
		if !pmOK {
			for i < len(children) && children[i].Decoder.Name == chainName {
				i++
			}
			continue
		}

		if d.Regex != nil || d.RegexFlex != nil {
			src := pickSlice(d.RegexOffset, fullLog, parentEnd, pmEnd, prevRegex)
			m, regEndVal, ok := runRegex(d, src)
			if !ok {
				for i < len(children) && children[i].Decoder.Name == chainName {
					i++
				}
				continue
			}
			applyOrderWithOffset(d, event, m)
			regEnd := regEndVal
			setDecoderNames(event, d)
			if len(child.Children) > 0 {
				runChildren(child.Children, event, fullLog, parentStart, regEnd)
			}
			if !d.GetNext {
				// Run remaining no-prematch chains as supplemental field extractors
				// e.g. auditd-generic runs after auditd-user_and_cred to extract res=
				j := i + 1
				for j < len(children) && children[j].Decoder.Name == chainName {
					j++
				}
				runSupplementalChains(children, j, event, fullLog)
				return
			}
			prevRegex = regEnd
			i++
			for i < len(children) && children[i].Decoder.Name == chainName {
				sib := children[i]
				sd := sib.Decoder
				if sd.Regex != nil || sd.RegexFlex != nil {
					// For OffsetFull siblings (no offset tag), always search fullLog.
					// This is essential for Sophos-style decoders where each sibling
					// independently extracts one field from the complete log line.
					sibSrc := pickSlice(sd.RegexOffset, fullLog, parentEnd, pmEnd, prevRegex)
					if sd.RegexOffset == OffsetFull {
						sibSrc = fullLog
					}
					sm, smAfter, smOK := runRegex(sd, sibSrc)
					if smOK {
						applyOrderWithOffset(sd, event, sm)
						// Only advance prevRegex for after_regex offset siblings
						if sd.RegexOffset == OffsetAfterRegex {
							prevRegex = smAfter
						}
						setDecoderNames(event, sd)
						if len(sib.Children) > 0 {
							runChildren(sib.Children, event, fullLog, parentStart, prevRegex)
						}
					}
				}
				i++
			}
			// Run remaining no-prematch chains as supplemental field extractors
			runSupplementalChains(children, i, event, fullLog)
			return
		}

		// Prematch-only child
		setDecoderNames(event, d)
		if len(child.Children) > 0 {
			runChildren(child.Children, event, fullLog, parentStart, prevRegex)
		}
		if !d.GetNext {
			// Run remaining no-prematch chains as supplemental field extractors
			j := i + 1
			for j < len(children) && children[j].Decoder.Name == d.Name {
				j++
			}
			runSupplementalChains(children, j, event, fullLog)
			return
		}
		i++
	}
}

// applyPrematchWithStart returns (afterEnd, fromMatchStart, ok).
// afterEnd   = log slice after the prematch match end (for offset=after_prematch)
// fromMatchStart = log slice from the match start (for offset=after_parent in children)
func applyPrematchWithStart(d *Decoder, fullLog, parentSlice, pmEnd, prevRegex string) (string, string, bool) {
	if d.Prematch == nil {
		s := parentSlice
		if s == "" {
			s = fullLog
		}
		return s, s, true
	}
	src := pickSlice(d.PrematchOffset, fullLog, parentSlice, pmEnd, prevRegex)
	loc := d.Prematch.FindStringIndex(src)
	if loc == nil {
		return "", "", false
	}
	return src[loc[1]:], src[loc[0]:], true
}

// applyOrderWithOffset maps capture groups to field names, correctly handling
// OR-combined regex patterns where groups from different alternatives have
// different starting indices.
// When two patterns are OR'd (r1|r2), r1 has groups 1..N and r2 has N+1..2N.
// We find the first non-empty group to determine which alternative matched.
func applyOrderWithOffset(d *Decoder, event *Event, m []string) {
	if len(d.Order) == 0 || len(m) <= 1 {
		return
	}
	// Find the first non-empty capture group
	offset := 1
	for offset < len(m) && m[offset] == "" {
		offset++
	}
	if offset >= len(m) {
		return
	}
	for i, name := range d.Order {
		idx := offset + i
		if idx < len(m) {
			name = strings.TrimSpace(name)
			if name != "" {
				event.SetNamedField(name, m[idx])
			}
		}
	}
}

func setDecoderNames(event *Event, d *Decoder) {
	event.DecoderName = d.Name
	if event.DecoderFamily == "" {
		event.DecoderFamily = d.Name
	}
}

func pickSlice(off OffsetType, full, parent, pmEnd, prevRegex string) string {
	switch off {
	case OffsetAfterParent:
		if parent != "" {
			return parent
		}
	case OffsetAfterPrematch:
		if pmEnd != "" {
			// Trim leading whitespace: lazy prematch quantifiers stop before trailing spaces,
			// e.g. "^Failed \S+ " prematch stops at "password" leaving " for root from..."
			// The regex "^for (\S+) from" needs to start at "for" not " for".
			return strings.TrimLeft(pmEnd, " \t")
		}
	case OffsetAfterRegex:
		if prevRegex != "" {
			return prevRegex
		}
		return full
	}
	return full
}

func matchProgName(d *Decoder, progName string) bool {
	if !d.HasProgName {
		return true
	}
	if d.ProgName == "" {
		return progName == ""
	}
	if d.ProgNameRe != nil {
		return d.ProgNameRe.MatchString(progName)
	}
	return strings.EqualFold(d.ProgName, progName)
}

func min2(a, b int) int { if a<b{return a}; return b }

// runRegex runs the primary (strict) regex and falls back to the flex version.
// Returns (match, afterEnd, found).
func runRegex(d *Decoder, src string) ([]string, string, bool) {
	if d.Regex != nil {
		m := d.Regex.FindStringSubmatch(src)
		if m != nil {
			loc := d.Regex.FindStringIndex(src)
			return m, src[loc[1]:], true
		}
	}
	// Strict failed — try flex version (handles FOS7 extra fields between captures)
	if d.RegexFlex != nil {
		m := d.RegexFlex.FindStringSubmatch(src)
		if m != nil {
			loc := d.RegexFlex.FindStringIndex(src)
			return m, src[loc[1]:], true
		}
	}
	return nil, "", false
}

// runSupplementalChains runs all remaining child chains that have NO prematch
// as supplemental field extractors. This mirrors Wazuh's behavior where
// "generic" decoder siblings (like auditd-generic) extract additional fields
// even after a more specific sibling (like auditd-user_and_cred) already fired.
// Only chains with OffsetFull regex and no prematch are considered supplemental.
func runSupplementalChains(children []*DecoderNode, startIdx int, event *Event, fullLog string) {
	i := startIdx
	for i < len(children) {
		d := children[i].Decoder
		chainName := d.Name
		// Only run chains with no prematch (they always match any log)
		if d.Prematch != nil {
			// Skip entire named chain
			for i < len(children) && children[i].Decoder.Name == chainName {
				i++
			}
			continue
		}
		// Run this chain and its GetNext siblings against fullLog.
		// Only set fields that are NOT already set by the specific decoder —
		// this prevents auditd-generic from overwriting "USER_AUTH" with "type=USER_AUTH".
		prevRegex := ""
		for i < len(children) && children[i].Decoder.Name == chainName {
			sd := children[i].Decoder
			if sd.Regex != nil || sd.RegexFlex != nil {
				src := fullLog
				if sd.RegexOffset == OffsetAfterRegex && prevRegex != "" {
					src = prevRegex
				}
				sm, smAfter, smOK := runRegex(sd, src)
				if smOK {
					// Apply only fields not already populated
					applyOrderWithOffsetIfEmpty(sd, event, sm)
					if sd.RegexOffset == OffsetAfterRegex {
						prevRegex = smAfter
					}
				}
			}
			i++
		}
	}
}

// applyOrderWithOffsetIfEmpty is like applyOrderWithOffset but skips fields
// that already have a value — used for supplemental generic decoder runs.
func applyOrderWithOffsetIfEmpty(d *Decoder, event *Event, m []string) {
	if len(d.Order) == 0 || len(m) <= 1 {
		return
	}
	offset := 1
	for offset < len(m) && m[offset] == "" {
		offset++
	}
	for fi, fieldName := range d.Order {
		gi := offset + fi
		if gi >= len(m) {
			break
		}
		val := m[gi]
		if val == "" {
			continue
		}
		// Only set if the field is currently empty
		if event.GetField(fieldName) == "" {
			event.SetNamedField(fieldName, val)
		}
	}
}
