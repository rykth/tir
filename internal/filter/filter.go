package filter

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/rykth/tir/internal/conn"
)

// Filter is a parsed query (the zero value matches every row)
type Filter struct {
	tokens []token
	raw    string
}

// Raw returns the source query string
func (f *Filter) Raw() string {
	if f == nil {
		return ""
	}
	return f.raw
}

// IsEmpty reports whether the filter has no tokens
func (f *Filter) IsEmpty() bool {
	return f == nil || len(f.tokens) == 0
}

type token struct {
	keyword string         // canonical keyword name ("" for global text/regex)
	value   string         // lowercased substring (regex is nil)
	regex   *regexp.Regexp // non-nil for regex tokens (case-insensitive)
}

// Parse compiles a query (returns nil + nil error for empty input)
func Parse(query string) (*Filter, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}
	f := &Filter{raw: query}
	for raw := range strings.FieldsSeq(query) {
		tok, err := parseToken(raw)
		if err != nil {
			return nil, fmt.Errorf("token %q: %w", raw, err)
		}
		f.tokens = append(f.tokens, tok)
	}
	return f, nil
}

func parseToken(s string) (token, error) {
	// global regex: /pattern/ (but not foo:/pattern/)
	if strings.HasPrefix(s, "/") {
		body, ok := strings.CutSuffix(s[1:], "/")
		if ok {
			re, err := regexp.Compile("(?i)" + body)
			if err != nil {
				return token{}, err
			}
			return token{regex: re}, nil
		}
	}

	// keyword:value
	if k, v, ok := strings.Cut(s, ":"); ok && k != "" {
		canon, known := canonicalKeyword(k)
		if !known {
			// unknown keyword (treat the whole thing as a substring search)
			return token{value: strings.ToLower(s)}, nil
		}
		// per-field regex (keyword:/pattern/)
		if strings.HasPrefix(v, "/") {
			if body, ok := strings.CutSuffix(v[1:], "/"); ok {
				re, err := regexp.Compile("(?i)" + body)
				if err != nil {
					return token{}, err
				}
				return token{keyword: canon, regex: re}, nil
			}
		}
		return token{keyword: canon, value: strings.ToLower(v)}, nil
	}

	// plain text (substring search across all fields)
	return token{value: strings.ToLower(s)}, nil
}

func canonicalKeyword(k string) (string, bool) {
	switch strings.ToLower(k) {
	case "port":
		return "port", true
	case "sport", "srcport", "source-port":
		return "sport", true
	case "dport", "dstport", "dest-port", "destination-port":
		return "dport", true
	case "src", "source":
		return "src", true
	case "dst", "dest", "destination":
		return "dst", true
	case "process", "proc":
		return "process", true
	case "sni", "host", "hostname":
		return "sni", true
	case "app", "application":
		return "app", true
	case "state":
		return "state", true
	case "proto", "protocol":
		return "proto", true
	default:
		return "", false
	}
}

// Match reports whether r passes every token (AND) - a nil/empty filter always
// matches
func (f *Filter) Match(r conn.ConnView) bool {
	if f.IsEmpty() {
		return true
	}
	for _, t := range f.tokens {
		if !matchToken(t, r) {
			return false
		}
	}
	return true
}

func matchToken(t token, r conn.ConnView) bool {
	switch t.keyword {
	case "":
		return matchGlobal(t, r)
	case "port":
		return matchPort(t, r.Key.LocalPort) || matchPort(t, r.Key.RemotePort)
	case "sport":
		return matchPort(t, r.Key.LocalPort)
	case "dport":
		return matchPort(t, r.Key.RemotePort)
	case "src":
		return matchSubstr(t, r.Key.LocalAddr.String())
	case "dst":
		return matchSubstr(t, r.Key.RemoteAddr.String())
	case "process":
		return matchSubstr(t, r.ProcessName)
	case "sni":
		return matchSubstr(t, r.DPI.Host)
	case "app":
		return matchSubstr(t, r.DPI.Protocol)
	case "state":
		return matchSubstr(t, r.State.String())
	case "proto":
		return matchSubstr(t, r.Key.Proto.String())
	}
	return false
}

func matchGlobal(t token, r conn.ConnView) bool {
	fields := []string{
		r.Key.Proto.String(),
		r.Key.LocalAddr.String(),
		strconv.Itoa(int(r.Key.LocalPort)),
		r.Key.RemoteAddr.String(),
		strconv.Itoa(int(r.Key.RemotePort)),
		r.State.String(),
		r.ProcessName,
		r.DPI.Protocol,
		r.DPI.Host,
		r.DPI.Version,
	}
	for _, f := range fields {
		if matchSubstr(t, f) {
			return true
		}
	}
	return false
}

func matchPort(t token, port uint16) bool {
	if t.regex != nil {
		return t.regex.MatchString(strconv.Itoa(int(port)))
	}
	// exact numeric match
	want, err := strconv.Atoi(t.value)
	if err != nil {
		return false
	}
	return int(port) == want
}

func matchSubstr(t token, s string) bool {
	s = strings.ToLower(s)
	if t.regex != nil {
		return t.regex.MatchString(s)
	}
	if t.value == "" {
		return false
	}
	return strings.Contains(s, t.value)
}
