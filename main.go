package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const defaultConf = "watchflux.conf"

func main() {
	confFile := flag.String("config", defaultConf, "Path to watchflux.conf")
	testLog := flag.String("test", "", "Test one log line and exit (wazuh-logtest mode)")
	interactiveMode := flag.Bool("interactive", false, "Interactive testing mode (-i)")
	flag.Parse()

	// Load config file
	c, err := loadConfig(*confFile)
	if err != nil {
		log.Fatalf("ERROR loading config %s: %v", *confFile, err)
	}

	// Override test log from CLI flag
	if *testLog != "" {
		c.TestLog = *testLog
	}

	p, err := NewPipeline(c)
	if err != nil {
		log.Fatalf("ERROR: %v", err)
	}
	defer p.Close()

	// Test mode (single log)
	if c.TestLog != "" {
		runTest(p, c.TestLog)
		return
	}

	// Interactive mode
	if *interactiveMode {
		runInteractive(p)
		return
	}

	// Production mode - syslog server
	printProductionBanner(c)
	StartSyslogServer(p)
}

// ═════════════════════════════════════════════════════════════════════════════
// CONFIG LOADING
// ═════════════════════════════════════════════════════════════════════════════

func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open config file: %w\n  Create %s or use -config /path/to/watchflux.conf", err, path)
	}
	defer f.Close()

	c := DefaultConfig()
	var decoderDirs, ruleDirs []string
	var decoderFiles, ruleFiles []string

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			return nil, fmt.Errorf("line %d: missing '=' in %q", lineNum, line)
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		// Strip inline comments
		if ci := strings.Index(val, " #"); ci >= 0 {
			val = strings.TrimSpace(val[:ci])
		}

		switch key {
		case "decoder_dir":
			decoderDirs = append(decoderDirs, val)
		case "rule_dir":
			ruleDirs = append(ruleDirs, val)
		case "decoder_file":
			decoderFiles = append(decoderFiles, val)
		case "rule_file":
			ruleFiles = append(ruleFiles, val)
		case "port":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: port must be a number: %v", lineNum, err)
			}
			c.Port = n
		case "tcp_port":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: tcp_port must be a number: %v", lineNum, err)
			}
			c.TCPPort = n
		case "agent":
			c.AgentName = val
			c.ManagerName = val
		case "agent_id":
			c.AgentID = val
		case "alerts_file":
			c.AlertsFile = val
		case "archives_file":
			c.ArchivesFile = val
		case "test":
			c.TestLog = val
		default:
			log.Printf("[config] unknown key %q on line %d — ignored", key, lineNum)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Expand decoder directories → sorted *.xml file list
	for _, dir := range decoderDirs {
		files, err := xmlFilesInDir(dir)
		if err != nil {
			return nil, fmt.Errorf("decoder_dir %q: %w", dir, err)
		}
		c.DecoderFiles = append(c.DecoderFiles, files...)
	}
	c.DecoderFiles = append(c.DecoderFiles, decoderFiles...)

	// Expand rule directories → sorted *.xml file list
	for _, dir := range ruleDirs {
		files, err := xmlFilesInDir(dir)
		if err != nil {
			return nil, fmt.Errorf("rule_dir %q: %w", dir, err)
		}
		c.RuleFiles = append(c.RuleFiles, files...)
	}
	c.RuleFiles = append(c.RuleFiles, ruleFiles...)

	if len(c.DecoderFiles) == 0 {
		return nil, fmt.Errorf("no decoder files found — set decoder_dir or decoder_file in %s", path)
	}
	if len(c.RuleFiles) == 0 {
		return nil, fmt.Errorf("no rule files found — set rule_dir or rule_file in %s", path)
	}

	return c, nil
}

func xmlFilesInDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read directory: %w", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".xml") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

// ═════════════════════════════════════════════════════════════════════════════
// PRODUCTION MODE
// ═════════════════════════════════════════════════════════════════════════════

func printProductionBanner(c *Config) {
	fmt.Println("\n╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║         WatchFlux SIEM Engine  v1.0                         ║")
	fmt.Println("║              Production Mode (Syslog Server)                ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  🔷 Agent       : %s (%s)\n", c.AgentName, c.AgentID)
	fmt.Printf("  🔷 UDP Port    : %d\n", c.Port)
	if c.TCPPort > 0 {
		fmt.Printf("  🔷 TCP Port    : %d\n", c.TCPPort)
	}
	fmt.Printf("  🔷 Decoders    : %d files loaded\n", len(c.DecoderFiles))
	fmt.Printf("  🔷 Rules       : %d files loaded\n", len(c.RuleFiles))
	fmt.Printf("  🔷 Alerts      : %s\n", c.AlertsFile)
	fmt.Printf("  🔷 Archives    : %s\n\n", c.ArchivesFile)
	fmt.Println("  Ready to receive logs...")
}

// ═════════════════════════════════════════════════════════════════════════════
// INTERACTIVE MODE (NEW SMART UX)
// ═════════════════════════════════════════════════════════════════════════════

func runInteractive(p *Pipeline) {
	printInteractiveBanner(p)
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("\n➤ Enter log (or command): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			continue
		}

		// Commands
		if strings.HasPrefix(input, "/") {
			handleCommand(input, p)
			continue
		}

		// Process log
		processLogInteractive(p, input, reader)
	}
}

func printInteractiveBanner(p *Pipeline) {
	fmt.Println("\n╔═══════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   WatchFlux Interactive Testing                          ║")
	fmt.Println("║              Smart Log Analysis & Decoder/Rule Testing                   ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════════════╝")

	fmt.Printf("\n📊 Loaded Resources:\n")
	fmt.Printf("  • Decoders: %d root + %d total\n", len(p.roots), countAllDecoders(p.roots))
	fmt.Printf("  • Rules: %d total\n", len(p.rules))

	fmt.Println(`
📝 Commands:
  /help              - Show all commands
  /list decoders     - List loaded decoders
  /list rules        - List loaded rules  
  /stats             - Show statistics
  /clear             - Clear screen
  /quit              - Exit

💡 Examples:
  Mar 21 13:45:32 sshd[1234]: Failed password for root from 10.5.3.2
  <34>1 2023-01-01T12:00:00Z host app - - message here
  severity=HIGH facility=AUTH: user=admin action=login`)
}

func handleCommand(cmd string, p *Pipeline) {
	parts := strings.Fields(strings.TrimPrefix(cmd, "/"))
	if len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "help":
		fmt.Println("\n📚 Available Commands:")
		fmt.Println("  /help              - Show this help message")
		fmt.Println("  /list decoders     - List all loaded decoders with hierarchy")
		fmt.Println("  /list rules        - List all loaded rules")
		fmt.Println("  /stats             - Show system statistics")
		fmt.Println("  /clear             - Clear the terminal")
		fmt.Println("  /quit              - Exit interactive mode")

	case "list":
		if len(parts) > 1 {
			switch parts[1] {
			case "decoders":
				listDecoders(p)
			case "rules":
				listRules(p)
			default:
				fmt.Printf("❌ Usage: /list [decoders|rules]\n")
			}
		} else {
			fmt.Printf("❌ Usage: /list [decoders|rules]\n")
		}

	case "stats":
		printStats(p)

	case "clear":
		fmt.Print("\033[2J\033[H")

	case "quit":
		fmt.Println("\n👋 Goodbye!")
		os.Exit(0)

	default:
		fmt.Printf("❌ Unknown command: %s (use /help for commands)\n", parts[0])
	}
}

func listDecoders(p *Pipeline) {
	if len(p.roots) == 0 {
		fmt.Println("  (no decoders loaded)")
		return
	}

	fmt.Printf("\n📋 Decoder Tree (%d root decoders, %d total)\n", len(p.roots), countAllDecoders(p.roots))
	fmt.Println(strings.Repeat("─", 80))

	for i, dec := range p.roots {
		printDecoderTree(dec, 0)
		if i < len(p.roots)-1 {
			fmt.Println()
		}
	}
	fmt.Println()
}

// FIXED: Correct field names from Decoder struct
func printDecoderTree(dec *DecoderNode, depth int) {
	indent := strings.Repeat("  ", depth)
	symbol := "├─"
	fmt.Printf("%s%s %s", indent, symbol, dec.Decoder.Name)
	
	// Prematch is *regexp.Regexp, not string
	if dec.Decoder.Prematch != nil {
		fmt.Printf(" [prematch]")
	}
	fmt.Println()

	for _, child := range dec.Children {
		printDecoderTree(child, depth+1)
	}
}

func listRules(p *Pipeline) {
	if len(p.rules) == 0 {
		fmt.Println("  (no rules loaded)")
		return
	}

	fmt.Printf("\n📋 Rules (%d total)\n", len(p.rules))
	fmt.Println(strings.Repeat("─", 110))
	fmt.Printf("%-6s %-6s %-10s %-20s %s\n", "ID", "LEVEL", "EMOJI", "DECODER", "DESCRIPTION")
	fmt.Println(strings.Repeat("─", 110))

	for _, r := range p.rules {
		decoder := r.DecodedAs
		if decoder == "" {
			decoder = "(any)"
		}
		desc := r.Description
		if len(desc) > 50 {
			desc = desc[:47] + "..."
		}
		emoji := levelEmoji(r.Level)
		fmt.Printf("%-6d %-6d %s%-9d %-20s %s\n", r.ID, r.Level, emoji, r.Level, decoder, desc)
	}
	fmt.Println()
}

func printStats(p *Pipeline) {
	fmt.Printf("\n📊 System Statistics\n")
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("  Root Decoders   : %d\n", len(p.roots))
	fmt.Printf("  Total Decoders  : %d\n", countAllDecoders(p.roots))
	fmt.Printf("  Rules Loaded    : %d\n", len(p.rules))

	// Count rules by level
	levelCounts := make(map[int]int)
	for _, r := range p.rules {
		levelCounts[r.Level]++
	}
	fmt.Printf("\n  Rules by Severity Level:\n")
	for level := 15; level >= 0; level-- {
		if count, ok := levelCounts[level]; ok {
			emoji := levelEmoji(level)
			fmt.Printf("    Level %2d %s : %d rules\n", level, emoji, count)
		}
	}
	fmt.Println()
}

func countAllDecoders(roots []*DecoderNode) int {
	count := 0
	var visit func(*DecoderNode)
	visit = func(n *DecoderNode) {
		count++
		for _, child := range n.Children {
			visit(child)
		}
	}
	for _, root := range roots {
		visit(root)
	}
	return count
}

func processLogInteractive(p *Pipeline, raw string, reader *bufio.Reader) {
	fmt.Println()
	printTestHeader()

	event, alerts := p.Process(raw, "127.0.0.1")

	// Phase 1: Envelope
	printPhase1(event)

	// Phase 2: Decoder
	printPhase2(event)

	// Phase 3: Rules
	printPhase3(alerts, event)

	// Output files
	printOutputSummary(alerts, p.cfg.AlertsFile, p.cfg.ArchivesFile)

	// Interactive options
	printInteractiveOptions(event, alerts, reader)
}

func printTestHeader() {
	fmt.Println(strings.Repeat("═", 80))
	fmt.Println("                        Log Processing Results")
	fmt.Println(strings.Repeat("═", 80))
}

func printPhase1(event *Event) {
	fmt.Println("\n🔷 PHASE 1: ENVELOPE PARSING")
	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("  Timestamp    : %s\n", event.Timestamp.Format("2006-01-02T15:04:05.000-0700"))
	fmt.Printf("  Hostname     : %s\n", orNone(event.Hostname))
	fmt.Printf("  Program      : %s\n", orNone(event.ProgramName))

	msg := event.Message
	if len(msg) > 80 {
		msg = msg[:77] + "…"
	}
	fmt.Printf("  Message      : %s\n", msg)
}

func printPhase2(event *Event) {
	fmt.Println("\n🔷 PHASE 2: DECODER MATCHING")
	fmt.Println(strings.Repeat("─", 80))

	if event.DecoderFamily == "" {
		fmt.Println("  ❌ No decoder matched")
		return
	}

	fmt.Printf("  ✅ Decoder Family : %s\n", event.DecoderFamily)
	if event.DecoderName != event.DecoderFamily {
		fmt.Printf("     Child Decoder  : %s\n", event.DecoderName)
	}

	fmt.Println("\n  Extracted Fields:")
	pf := func(label, val string) {
		if val != "" {
			fmt.Printf("    %-16s : %s\n", label, val)
		}
	}
	pf("Source IP", event.SrcIP)
	pf("Dest IP", event.DstIP)
	pf("Source Port", event.SrcPort)
	pf("Dest Port", event.DstPort)
	pf("Source User", event.SrcUser)
	pf("Dest User", event.DstUser)
	pf("Action", event.Action)
	pf("Status", event.Status)
	pf("Protocol", event.Protocol)
	pf("URL", event.URL)
	pf("Extra Data", event.Extra)

	if len(event.KVFields) > 0 {
		fmt.Printf("\n  Additional KV Fields (%d):\n", len(event.KVFields))
		count := 0
		for k, v := range event.KVFields {
			if count >= 10 {
				fmt.Printf("    ... and %d more\n", len(event.KVFields)-10)
				break
			}
			if len(v) > 50 {
				v = v[:47] + "…"
			}
			fmt.Printf("    %-16s : %s\n", k, v)
			count++
		}
	}
}

func printPhase3(alerts []*Rule, event *Event) {
	fmt.Println("\n🔷 PHASE 3: RULE EVALUATION")
	fmt.Println(strings.Repeat("─", 80))

	if len(alerts) == 0 {
		fmt.Println("  ℹ️  No alert rules matched")
		return
	}

	fmt.Printf("  ✅ %d rule(s) matched:\n\n", len(alerts))
	for _, r := range alerts {
		desc := resolveDescription(r.Description, event)
		emoji := levelEmoji(r.Level)
		fmt.Printf("  %s [Rule %d] Level %d - %s\n", emoji, r.ID, r.Level, desc)
		if len(r.MITRE) > 0 {
			fmt.Printf("     MITRE ATT&CK: %s\n", strings.Join(r.MITRE, ", "))
		}
		if len(r.PCI) > 0 {
			fmt.Printf("     PCI-DSS: %s\n", strings.Join(r.PCI, ", "))
		}
		if len(r.GDPR) > 0 {
			fmt.Printf("     GDPR: %s\n", strings.Join(r.GDPR, ", "))
		}
	}
}

func printOutputSummary(alerts []*Rule, alertsFile, archivesFile string) {
	fmt.Println("\n🔷 OUTPUT FILES")
	fmt.Println(strings.Repeat("─", 80))

	if len(alerts) > 0 {
		fmt.Printf("  ✅ Alert written   → %s\n", alertsFile)
	}
	fmt.Printf("  ✅ Archive written → %s\n", archivesFile)
}

func printInteractiveOptions(event *Event, alerts []*Rule, reader *bufio.Reader) {
	fmt.Println("\n" + strings.Repeat("─", 80))
	fmt.Print("  Options: [Enter] continue | [q] quit: ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "q":
		fmt.Println("\n👋 Goodbye!")
		os.Exit(0)
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// TEST MODE (original, preserved)
// ═════════════════════════════════════════════════════════════════════════════

func runTest(p *Pipeline, raw string) {
	fmt.Println("\n╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║   WatchFlux Log Test  (wazuh-logtest mode)                   ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Printf("Input log:\n  %s\n\n", raw)

	event, alerts := p.Process(raw, "127.0.0.1")

	fmt.Println("── Phase 1: Envelope ───────────────────────────────────────────")
	fmt.Printf("  Timestamp    : %s\n", event.Timestamp.Format("2006-01-02T15:04:05.000-0700"))
	fmt.Printf("  Hostname     : %s\n", orNone(event.Hostname))
	fmt.Printf("  Program      : %s\n", orNone(event.ProgramName))
	msg := event.Message
	if len(msg) > 160 {
		msg = msg[:160] + "…"
	}
	fmt.Printf("  Message      : %s\n", msg)

	fmt.Println("\n── Phase 2: Decoder ────────────────────────────────────────────")
	if event.DecoderFamily == "" {
		fmt.Println("  (no decoder matched)")
	} else {
		fmt.Printf("  decoder.name : %s\n", event.DecoderFamily)
		fmt.Printf("  decoder.child: %s\n", event.DecoderName)
		pf := func(label, val string) {
			if val != "" {
				fmt.Printf("  %-14s : %s\n", label, val)
			}
		}
		pf("srcip", event.SrcIP)
		pf("dstip", event.DstIP)
		pf("srcport", event.SrcPort)
		pf("dstport", event.DstPort)
		pf("srcuser", event.SrcUser)
		pf("dstuser", event.DstUser)
		pf("action", event.Action)
		pf("status", event.Status)
		pf("protocol", event.Protocol)
		pf("url", event.URL)
		pf("extra_data", event.Extra)
		if len(event.KVFields) > 0 {
			fmt.Printf("\n  ── data block (%d fields) ───────────────────────────\n", len(event.KVFields))
			for k, v := range event.KVFields {
				fmt.Printf("    %-24s : %s\n", k, v)
			}
		}
	}

	fmt.Println("\n── Phase 3: Rules ──────────────────────────────────────────────")
	if len(alerts) == 0 {
		fmt.Println("  (no alert rules matched)")
	} else {
		for _, r := range alerts {
			desc := resolveDescription(r.Description, event)
			fmt.Printf("  %s  rule=%-5d  level=%-2d  %s\n",
				levelEmoji(r.Level), r.ID, r.Level, desc)
			if len(r.MITRE) > 0 {
				fmt.Printf("              MITRE  : %s\n", strings.Join(r.MITRE, ", "))
			}
			if len(r.PCI) > 0 {
				fmt.Printf("              PCI    : %s\n", strings.Join(r.PCI, ", "))
			}
			if len(r.GDPR) > 0 {
				fmt.Printf("              GDPR   : %s\n", strings.Join(r.GDPR, ", "))
			}
			if len(r.HIPAA) > 0 {
				fmt.Printf("              HIPAA  : %s\n", strings.Join(r.HIPAA, ", "))
			}
			if len(r.NIST) > 0 {
				fmt.Printf("              NIST   : %s\n", strings.Join(r.NIST, ", "))
			}
			if len(r.TSC) > 0 {
				fmt.Printf("              TSC    : %s\n", strings.Join(r.TSC, ", "))
			}
		}
	}

	fmt.Println("\n── Output ──────────────────────────────────────────────────────")
	if len(alerts) > 0 {
		fmt.Printf("  ✓ alert   written → %s\n", p.cfg.AlertsFile)
	}
	fmt.Printf("  ✓ archive written → %s\n", p.cfg.ArchivesFile)
	fmt.Println("════════════════════════════════════════════════════════════════")
}

// ═════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═════════════════════════════════════════════════════════════════════════���═══

func levelEmoji(level int) string {
	switch {
	case level >= 12:
		return "🔴"
	case level >= 8:
		return "🔴"
	case level >= 6:
		return "🟠"
	case level >= 4:
		return "🟡"
	case level > 0:
		return "🟢"
	default:
		return "  "
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func resolveDescription(desc string, event *Event) string {
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
