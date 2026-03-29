package main

// ParseKV parses a Fortigate key=value log line into a flat map.
//
// Handles all three Fortigate value formats:
//   key=value           (unquoted)
//   key="value"         (double-quoted, may contain spaces)
//   key="val(inner)"    (quoted with parens, e.g. ui="https(1.2.3.4)")
//
// Special case: the "msg" field often contains spaces and is always quoted.
// This parser correctly handles it because it reads until the closing '"'
// followed by a space or end-of-string.
func ParseKV(s string) map[string]string {
	m := make(map[string]string, 40)
	i := 0
	n := len(s)

	for i < n {
		// skip whitespace
		for i < n && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}

		// read key
		keyStart := i
		for i < n && s[i] != '=' && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		if i >= n || s[i] != '=' {
			for i < n && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			continue
		}
		key := s[keyStart:i]
		i++ // skip '='

		if i >= n {
			if key != "" {
				m[key] = ""
			}
			break
		}

		var value string
		if s[i] == '"' {
			i++ // skip opening '"'
			valStart := i
			for i < n {
				if s[i] == '"' {
					// closing quote = end-of-string OR next char is space
					if i+1 >= n || s[i+1] == ' ' || s[i+1] == '\t' {
						break
					}
				}
				i++
			}
			value = s[valStart:i]
			if i < n && s[i] == '"' {
				i++
			}
		} else {
			valStart := i
			for i < n && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			value = s[valStart:i]
		}

		if key != "" {
			m[key] = value
		}
	}
	return m
}
