package dpi

import (
	"regexp"
	"strconv"
	"strings"

	"awg-split-tunnel/internal/core"
)

// winwsLineRe matches lines containing winws.exe invocations in .bat files.
var winwsLineRe = regexp.MustCompile(`(?i)winws\.exe\s+(.+)`)

// ParseBatFile parses a zapret .bat file and extracts DPI bypass strategies.
// Each winws.exe invocation becomes a Strategy; --new separates DesyncOps within a strategy.
func ParseBatFile(content string, name string) (*Strategy, error) {
	var allOps []DesyncOp

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		// Skip comments and empty lines.
		if line == "" || strings.HasPrefix(line, "REM") || strings.HasPrefix(line, "rem") || strings.HasPrefix(line, "::") {
			continue
		}

		m := winwsLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		argsStr := m[1]
		// Handle bat line continuation (^ at end).
		argsStr = strings.ReplaceAll(argsStr, "^", "")
		argsStr = strings.TrimSpace(argsStr)

		ops := parseWinwsArgs(argsStr)
		allOps = append(allOps, ops...)
	}

	if len(allOps) == 0 {
		core.Log.Debugf("DPI", "No winws.exe invocations found in %q", name)
		return &Strategy{Name: name, Source: "zapret"}, nil
	}

	return &Strategy{
		Name:   name,
		Source: "zapret",
		Ops:    allOps,
	}, nil
}

// parseWinwsArgs parses the argument string of a single winws.exe invocation.
// Arguments are split by --new into separate DesyncOps.
func parseWinwsArgs(argsStr string) []DesyncOp {
	blocks := splitByNew(argsStr)

	var ops []DesyncOp
	for _, block := range blocks {
		op := parseOpBlock(block)
		op.Defaults()
		ops = append(ops, op)
	}
	return ops
}

// splitByNew splits args string by the --new delimiter.
func splitByNew(argsStr string) []string {
	tokens := tokenize(argsStr)

	var blocks []string
	var current []string

	for _, tok := range tokens {
		if tok == "--new" {
			if len(current) > 0 {
				blocks = append(blocks, strings.Join(current, " "))
				current = nil
			}
		} else {
			current = append(current, tok)
		}
	}
	if len(current) > 0 {
		blocks = append(blocks, strings.Join(current, " "))
	}
	return blocks
}

// tokenize splits a command-line string into tokens, handling quoted values.
func tokenize(s string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote:
			if c == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(c)
			}
		case c == '"' || c == '\'':
			inQuote = true
			quoteChar = c
		case c == ' ' || c == '\t':
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// parseOpBlock parses a single block of winws arguments into a DesyncOp.
func parseOpBlock(block string) DesyncOp {
	tokens := tokenize(block)
	var op DesyncOp

	for i := 0; i < len(tokens); i++ {
		key, val := parseArg(tokens, i)
		if val != "" && !strings.HasPrefix(val, "--") {
			i++ // consumed next token as value
		}

		switch key {
		case "--dpi-desync":
			op.Mode = parseDesyncMode(val)
		case "--dpi-desync-split-pos":
			op.SplitPos = parseSplitPos(val)
		case "--dpi-desync-fooling":
			op.Fool = parseFoolMethods(val)
		case "--dpi-desync-repeats":
			if n, err := strconv.Atoi(val); err == nil {
				op.Repeats = n
			}
		case "--dpi-desync-ttl":
			if n, err := strconv.Atoi(val); err == nil {
				op.FakeTTL = n
			}
		case "--dpi-desync-fake-tls":
			// Store the filename reference; actual binary loaded separately by fetcher.
			op.Cutoff = "fake_tls_file:" + val
		case "--dpi-desync-split-seqovl":
			if n, err := strconv.Atoi(val); err == nil {
				op.SplitSeqOvl = n
			}
		case "--dpi-desync-cutoff":
			op.Cutoff = val
		case "--filter-tcp":
			op.FilterPorts = parsePorts(val)
			op.FilterProtocol = "tcp"
		case "--filter-udp":
			op.FilterPorts = parsePorts(val)
			op.FilterProtocol = "udp"
		// Ignored zapret-specific flags.
		case "--hostlist", "--hostlist-exclude", "--ipset", "--ipset-exclude",
			"--hostlist-auto", "--wf-tcp", "--wf-udp", "--wf-raw":
		}
	}

	return op
}

// parseArg extracts key=value or key value pairs from tokens.
func parseArg(tokens []string, i int) (key, val string) {
	tok := tokens[i]
	if idx := strings.Index(tok, "="); idx > 0 {
		return tok[:idx], tok[idx+1:]
	}
	// Value in next token.
	if i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "--") {
		return tok, tokens[i+1]
	}
	return tok, ""
}

// parseDesyncMode maps zapret mode strings to DesyncMode.
func parseDesyncMode(s string) DesyncMode {
	switch strings.ToLower(s) {
	case "fake":
		return DesyncFake
	case "multisplit":
		return DesyncMultisplit
	case "fakedsplit":
		return DesyncFakedsplit
	case "multidisorder":
		return DesyncMultidisorder
	case "split":
		return DesyncMultisplit
	case "disorder":
		return DesyncMultidisorder
	case "none":
		return DesyncNone
	default:
		// Try comma-separated compound modes.
		for _, part := range strings.Split(s, ",") {
			m := parseDesyncMode(part)
			if m != "" {
				return m
			}
		}
		return DesyncMultisplit
	}
}

// parseSplitPos parses comma-separated split positions.
// Special values: "midsld", "sniext" → auto SNI (0).
func parseSplitPos(s string) []int {
	var positions []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		switch strings.ToLower(part) {
		case "midsld", "sniext", "sni", "auto":
			positions = append(positions, SplitPosAutoSNI)
		default:
			if n, err := strconv.Atoi(part); err == nil {
				positions = append(positions, n)
			}
		}
	}
	return positions
}

// parseFoolMethods parses comma-separated fool methods.
func parseFoolMethods(s string) []FoolMethod {
	var methods []FoolMethod
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		switch part {
		case "badsum":
			methods = append(methods, FoolBadSum)
		case "badseq":
			methods = append(methods, FoolBadSeq)
		case "ttl":
			methods = append(methods, FoolTTL)
		case "md5sig":
			methods = append(methods, FoolMD5Sig)
		case "ts":
			methods = append(methods, FoolTTL)
		}
	}
	return methods
}

// parsePorts parses comma-separated port numbers.
func parsePorts(s string) []int {
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if n, err := strconv.Atoi(part); err == nil && n > 0 && n <= 65535 {
			ports = append(ports, n)
		}
	}
	return ports
}
