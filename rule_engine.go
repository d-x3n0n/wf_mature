package main

import (
	"sync"
	"time"
)

// ─── Sliding-window frequency tracker ────────────────────────────────────────
// Mirrors Wazuh's EventList mechanism (analysisd/eventq.c).

var (
	freqMu    sync.Mutex
	freqStore = map[freqKey]*freqEntry{}
)

type freqKey struct {
	ruleID int
	srcIP  string // empty string = any source (when same_source_ip is not set)
}

type freqEntry struct {
	times []time.Time
}

// recordAndCheck adds a hit and returns true when the sliding window count
// has reached `threshold` within `timeframeSec` seconds.
func recordAndCheck(ruleID, threshold, timeframeSec int, srcIP string) bool {
	if threshold <= 0 {
		return true
	}
	now := time.Now()
	cutoff := now.Add(-time.Duration(timeframeSec) * time.Second)
	key := freqKey{ruleID, srcIP}

	freqMu.Lock()
	defer freqMu.Unlock()

	e := freqStore[key]
	if e == nil {
		e = &freqEntry{}
		freqStore[key] = e
	}

	// Expire old entries
	fresh := e.times[:0]
	for _, t := range e.times {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, now)
	e.times = fresh

	return len(e.times) >= threshold
}

// ─── Rule evaluation ──────────────────────────────────────────────────────────

// EvaluateRules checks every rule against the event and returns all that match.
// Matched SIDs accumulate on event.MatchedSIDs so if_sid chains work within
// the same event (mirrors Wazuh's analysisd alert loop).
func EvaluateRules(event *Event, rules []*Rule) []*Rule {
	var matched []*Rule
	for _, r := range rules {
		ok := matchRule(r, event)
		if ok {
			event.MatchedSIDs = append(event.MatchedSIDs, r.ID)
			matched = append(matched, r)
		}
	}
	return matched
}

func matchRule(r *Rule, event *Event) bool {

	// 1. decoded_as — matches the decoder family (root name) OR specific child.
	//    Wazuh child decoders share their parent's decoder ID, so decoded_as
	//    effectively matches any decoder in the family.
	if r.DecodedAs != "" {
		if r.DecodedAs != event.DecoderName && r.DecodedAs != event.DecoderFamily {
			return false
		}
	}

	// 2. if_sid — at least one listed SID must have already fired this event.
	if len(r.IfSIDs) > 0 {
		found := false
		for _, sid := range r.IfSIDs {
			if hasSIDInList(sid, event.MatchedSIDs) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// 3. if_matched_sid — frequency-based correlation.
	//    Referenced SID must have fired AND sliding window must hit threshold.
	if len(r.IfMatchedSIDs) > 0 {
		found := false
		for _, sid := range r.IfMatchedSIDs {
			if hasSIDInList(sid, event.MatchedSIDs) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		freq := r.Frequency
		if freq == 0 {
			freq = 2
		}
		tf := r.Timeframe
		if tf == 0 {
			tf = 60
		}
		ip := ""
		if r.SameSourceIP {
			ip = event.SrcIP
		}
		if !recordAndCheck(r.ID, freq, tf, ip) {
			return false
		}
	}

	// 4. Text match on full raw message
	if !r.Match.MatchString(event.Message) {
		return false
	}
	if !r.Regex.MatchString(event.Message) {
		return false
	}

	// 5. Decoded field conditions
	if !r.SrcIPPat.MatchString(event.SrcIP) {
		return false
	}
	if !r.DstIPPat.MatchString(event.DstIP) {
		return false
	}
	if !r.UserPat.MatchString(event.SrcUser) {
		return false
	}
	if !r.StatusPat.MatchString(event.Status) {
		return false
	}
	if !r.ActionPat.MatchString(event.Action) {
		return false
	}
	if !r.URLPat.MatchString(event.URL) {
		return false
	}
	if !r.ProtocolPat.MatchString(event.Protocol) {
		return false
	}

	// 6. Dynamic <field name="x"> conditions
	// Matches against event.GetField which checks DynFields, KVFields, and named fields.
	// This is how Cisco IOS rules match cisco.facility, cisco.severity, cisco.mnemonic.
	for _, fr := range r.FieldRules {
		val := event.GetField(fr.Name)
		if !fr.Pattern.MatchString(val) {
			return false
		}
	}

	// 7. Standalone frequency (no if_matched_sid) — rule fires only after N hits
	if r.Frequency > 0 && len(r.IfMatchedSIDs) == 0 {
		tf := r.Timeframe
		if tf == 0 {
			tf = 60
		}
		ip := ""
		if r.SameSourceIP {
			ip = event.SrcIP
		}
		if !recordAndCheck(r.ID, r.Frequency, tf, ip) {
			return false
		}
	}

	return true
}
