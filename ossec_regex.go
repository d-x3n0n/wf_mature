package main

import (
	"regexp"
	"strings"
)

// translateOSSEC converts OSSEC regex syntax → Go regexp syntax.
//
// OSSEC escapes:
//   \.  → [^\n]    any single non-newline char
//   \w  → \S       non-space (broader than [a-zA-Z0-9_], handles quoted FOS values)
//   \W  → \s
//   \p  → [^\s\x00-\x1f]  printable non-space
//   \d  → [0-9]
//   \D  → [^0-9]
//   \s  → [ \t]
//   \S  → [^ \t]
//   .   → \.       OSSEC bare dot = literal dot (opposite of standard regex)
//
// Literal [ and ] in OSSEC patterns (e.g. in Cisco IDS: [1.2.3.4:80 -> ...])
// are treated as literal bracket characters, not character class delimiters.
// We escape them as \[ and \].
// Note: char classes we generate ourselves (like [^\n], [0-9]) are appended
// as raw bytes and are NOT passed through this escape — they remain valid.
func translateOSSEC(s string) string {
	out := make([]byte, 0, len(s)*2)
	n := len(s)
	for i := 0; i < n; {
		c := s[i]

		if c == '\\' && i+1 < n {
			next := s[i+1]
			i += 2
			switch next {
			case '.':
				// OSSEC \. = any single non-newline char (like . in PCRE)
				out = append(out, '[', '^', '\n', ']')
			case 'w':
				// OSSEC \w = word characters [A-Za-z0-9_]
				out = append(out, '[', 'A', '-', 'Z', 'a', '-', 'z', '0', '-', '9', '_', ']')
			case 'W':
				out = append(out, '\\', 's')
			case 'p':
				out = append(out, '[', '^', '\\', 's', '\\', 'x', '0', '0', '-', '\\', 'x', '1', 'f', ']')
			case 'd':
				out = append(out, '[', '0', '-', '9', ']')
			case 'D':
				out = append(out, '[', '^', '0', '-', '9', ']')
			case 's':
				out = append(out, '[', ' ', '\\', 't', ']')
			case 'S':
				out = append(out, '[', '^', ' ', '\\', 't', ']')
			case 't':
				out = append(out, '\\', 't')
			case 'n':
				out = append(out, '\\', 'n')
			default:
				out = append(out, '\\', next)
			}
			continue
		}

		// Bare '.' in OSSEC = literal dot (not "any char")
		if c == '.' {
			out = append(out, '\\', '.')
			i++
			continue
		}

		// Bare '[' or ']' in OSSEC input = literal bracket character
		// (used as log delimiters in Cisco IDS: [1.2.3.4:port -> ...])
		// Must be escaped so Go regexp doesn't treat them as char class delimiters.
		if c == '[' || c == ']' {
			out = append(out, '\\', c)
			i++
			continue
		}

		out = append(out, c)
		i++
	}
	return string(out)
}

// compileOSSEC compiles a plain OSSEC regex (no flex-spaces).
func compileOSSEC(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + translateOSSEC(pattern))
}

// compileRegex compiles an OSSEC <regex> pattern.
// NOTE: We do NOT apply flexifySpaces here — that would break capture group
// ordering in precisely-structured regexes like Cisco ACL IP captures.
// Flex-spaces is only for <prematch> patterns.
func compileRegex(pattern string) (*regexp.Regexp, error) {
	translated := translateOSSEC(pattern)
	translated = makeLazy(translated)
	return regexp.Compile("(?i)" + translated)
}

// compilePrematch compiles an OSSEC <prematch> with full FOS6/7 compatibility:
//  1. translateOSSEC   — OSSEC escapes → Go regexp
//  2. makeValuesQuoteOptional — key=value works for both quoted and unquoted logs
//  3. flexifySpaces    — spaces → [^\n]* to allow extra fields between tokens
func compilePrematch(pattern string) (*regexp.Regexp, error) {
	translated := translateOSSEC(pattern)
	quoted := makeValuesQuoteOptional(translated)
	flexed := flexifySpaces(quoted)
	lazy := makeLazy(flexed)      // lazy quantifiers prevent greedy match consuming entire log
	// Append optional trailing whitespace consumer so prematch patterns like
	// "^Failed \S+ " (where trailing space becomes [^\n]*? via flexify+lazy)
	// actually consume the space. This ensures after_prematch regex src starts
	// cleanly at the next word (e.g. "for root from..." not " for root from...").
	return regexp.Compile("(?i)" + lazy)
}

// makeValuesQuoteOptional wraps =<token> so it matches both unquoted (FOS5)
// and quoted (FOS6/7) log formats.
func makeValuesQuoteOptional(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	i, n := 0, len(s)
	for i < n {
		if s[i] != '=' {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteByte('=')
		i++
		if i >= n {
			break
		}
		if strings.HasPrefix(s[i:], `(?:`) {
			continue
		}
		if s[i] == '"' {
			b.WriteString(`(?:"?)`)
			i++
			j, depth := i, 0
			for j < n {
				switch s[j] {
				case '[':
					depth++
				case ']':
					if depth > 0 {
						depth--
					}
				case '"':
					if depth == 0 {
						goto closingFound
					}
				}
				j++
			}
		closingFound:
			inner := s[i:j]
			inner = strings.ReplaceAll(inner, `[^\n]+`, `[^\n]+?`)
			inner = strings.ReplaceAll(inner, `[^\n]*`, `[^\n]*?`)
			b.WriteString(inner)
			b.WriteString(`(?:"?)`)
			if j < n && s[j] == '"' {
				j++
			}
			i = j
			continue
		}
		if s[i] == '\\' || s[i] == '[' {
			b.WriteString(`(?:"?)`)
			j, depth := i, 0
			for j < n && (s[j] != ' ' || depth > 0) {
				switch s[j] {
				case '[':
					depth++
				case ']':
					if depth > 0 {
						depth--
					}
				}
				j++
			}
			b.WriteString(s[i:j])
			b.WriteString(`(?:"?)`)
			i = j
			continue
		}
		if isWordChar(s[i]) {
			b.WriteString(`(?:"?)`)
			j := i
			for j < n && isWordChar(s[j]) {
				j++
			}
			b.WriteString(s[i:j])
			b.WriteString(`(?:"?)`)
			i = j
			continue
		}
	}
	return b.String()
}

func isWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'
}

// flexifySpaces replaces spaces between tokens with [^\n]* so extra fields
// inserted by newer FortiOS versions don't break prematch.
func flexifySpaces(s string) string {
	var b strings.Builder
	inClass := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '[':
			inClass++
			b.WriteByte(c)
		case c == ']' && inClass > 0:
			inClass--
			b.WriteByte(c)
		case c == ' ' && inClass == 0:
			b.WriteString("[^\n]*")  // actual newline byte so makeLazy can find and lazify it
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// compileRegexFlex compiles an OSSEC <regex> with flex-spaces applied.
// Used as a fallback when the strict version fails to match — handles
// Fortigate FOS6/7 logs where extra fields appear between captured fields.
func compileRegexFlex(pattern string) (*regexp.Regexp, error) {
	translated := translateOSSEC(pattern)
	translated = makeLazy(translated)
	flexed := flexifySpaces(translated)
	return regexp.Compile("(?i)" + flexed)
}

// makeLazy converts greedy [^\n]* and [^\n]+ to their lazy equivalents.
// IMPORTANT: uses double-quoted strings so \n = actual newline byte (0x0A),
// matching what translateOSSEC generates (it appends the literal byte \n).
// Raw-string backtick literals like `[^\n]*` contain backslash+n (2 chars)
// which would NOT match the generated output.
func makeLazy(s string) string {
	// Guard already-lazy forms first so we don't double-process
	s = strings.ReplaceAll(s, "[^\n]*?", "\x00LAZY_STAR\x00")
	s = strings.ReplaceAll(s, "[^\n]+?", "\x00LAZY_PLUS\x00")
	s = strings.ReplaceAll(s, "[^\n]*",  "[^\n]*?")
	s = strings.ReplaceAll(s, "[^\n]+",  "[^\n]+?")
	s = strings.ReplaceAll(s, "\x00LAZY_STAR\x00", "[^\n]*?")
	s = strings.ReplaceAll(s, "\x00LAZY_PLUS\x00", "[^\n]+?")
	return s
}
