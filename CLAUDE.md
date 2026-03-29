# WatchFlux Development Guidelines

## Build & Test
```bash
# Build
go build -o watchflux
go test ./...

# Test single log line
./watchflux -test 'your log here'

# Run with default config
./watchflux -config watchflux.conf
```

## Code Style
- Go 1.22.2, stdlib only (zero external deps)
- Decoder/rule XML format: Wazuh/OSSEC compatible
- All events flow through 3-phase pipeline: predecode → decode → evaluate
- Event struct is the central data object through entire pipeline

## Key Gotchas
- **ALL rules evaluated per event**: Not a decision tree—multiple rules can fire
- **if_sid chaining**: Rules depend on other rules matched in same event
- **Frequency correlation**: Sliding windows—events outside timeframe expire
- **Quoted values**: FOS6/7 logs quote all fields, decoder strips quotes
- **Flex regex**: Decoders have strict+flex patterns for extra field compatibility
- **Decoder inheritance**: Child decoders extend parent fields, shared children
- **Ports**: 514 requires root; use 5140 (UDP)/5141 (TCP) without sudo
- **Syslog formats**: Supports both RFC5424 (structured) and RFC3164 (legacy)

## Configuration
- Config: simple key=value format in `watchflux.conf`
- Decoders: `ruleset/decoders/*.xml` (sorted alphanumerically)
- Rules: `ruleset/rules/*.xml` (sorted alphanumerically)
- Output: `logs/alerts.json`, `logs/archives.json` + optional OpenSearch