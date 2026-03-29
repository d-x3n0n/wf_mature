# WatchFlux SIEM Engine - Architecture Documentation

## System Overview

**WatchFlux** is a lightweight, high-performance SIEM (Security Information and Event Management) engine written in Go. It processes syslog messages, parses them using XML-based decoders, evaluates security rules, and generates alerts. The system is designed to be **Wazuh/OSSEC compatible** while providing a simplified, dependency-free implementation.

### Core Purpose

WatchFlux serves as the central log processing engine for security monitoring:
- **Ingestion**: Receives syslog logs via UDP/TCP from various sources
- **Parsing**: Decodes logs using hierarchical decoder trees
- **Correlation**: Evaluates security rules with advanced correlation features
- **Alerting**: Generates structured alerts and archives
- **Export**: Outputs to local JSON files and/or OpenSearch/Elasticsearch

### Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| **Language** | Go (Golang) | 1.22.2 |
| **Dependencies** | Standard Library Only | - |
| **Configuration** | Simple key=value format | Custom |
| **Rule Format** | XML (Wazuh/OSSEC compatible) | - |
| **Output Formats** | JSON, OpenSearch HTTP API | - |
| **Protocols** | UDP, TCP (syslog) | RFC3164, RFC5424 |

### Key Features

- **Zero External Dependencies**: Pure Go implementation using only stdlib
- **Wazuh Compatibility**: Supports Wazuh/OSSEC decoder and rule XML formats
- **Dual Protocol Support**: UDP (fire-and-forget) and TCP (reliable delivery)
- **Flexible Decoding**: Hierarchical decoder trees with parent-child inheritance
- **Advanced Correlation**: Sliding-window frequency, if_sid chaining, field matching
- **Compliance Tags**: PCI, GDPR, HIPAA, NIST, GPG13, TSC, MITRE integration
- **Multi-Output**: Local JSON files + OpenSearch/Elasticsearch
- **Test Mode**: Wazuh-logtest compatibility for rule debugging

---

## Directory Structure

```
watchflux_final/
├── main.go                 # Entry point, config loading, CLI flags
├── event.go                # Event data structure (core pipeline object)
├── pipeline.go             # 3-phase processing pipeline orchestration
├── syslog_server.go        # UDP/TCP syslog listeners
├── decoder_model.go        # Decoder data structures
├── decoder_tree.go         # Decoder tree building & matching logic
├── rule_model.go           # Rule data structures & patterns
├── rule_engine.go          # Rule evaluation & frequency correlation
├── predecoder.go           # RFC5424/3164 syslog envelope parsing
├── kv_parser.go            # Key=value parser for log fields
├── json_decoder.go         # JSON log format decoder
├── ossec_regex.go          # OSSEC/Wazuh regex extensions
├── xml_loader.go           # XML decoder/rule file parser
├── output.go               # JSON alert/archive output formatting
├── opensearch.go           # OpenSearch HTTP client
├── watchflux.conf          # Configuration file
├── go.mod                  # Go module definition
├── watchflux               # Compiled binary
├── watchflux-linux-amd64   # Pre-built Linux binary
├── etc/
│   └── lists/              # External data lists for rule lookups
├── ruleset/
│   ├── decoders/           # XML decoder definitions (*.xml)
│   │   ├── 0006-json_decoders.xml
│   │   ├── 0100-fortigate_decoders.xml
│   │   ├── 0065-cisco-ios_decoders.xml
│   │   └── ...
│   └── rules/              # XML rule definitions (*.xml)
│       ├── 0080-sonicwall_rules.xml
│       ├── 0390-fortigate_rules.xml
│       ├── 0075-cisco-ios_rules.xml
│       └── ...
├── logs/                   # Output files (alerts.json, archives.json)
└── .claude/                # Claude Code memory files
```

### File Explanations

**Core Application Files:**
- `main.go`: Application entry point, configuration parser, CLI flag handling
- `event.go`: Central data structure representing a log event through all pipeline stages
- `pipeline.go`: Orchestrates the 3-phase processing (predecode → decode → evaluate)

**Network & Input:**
- `syslog_server.go`: UDP and TCP syslog listeners with connection management

**Decoding System:**
- `decoder_model.go`: Decoder data structures and field mapping definitions
- `decoder_tree.go`: Hierarchical decoder tree construction and traversal logic
- `predecoder.go`: Syslog envelope parsing (RFC5424/3164) and field extraction
- `kv_parser.go`: Key=value field parser for unstructured log content
- `json_decoder.go`: JSON log format parsing and field extraction
- `ossec_regex.go`: OSSEC/Wazuh-specific regex extensions and patterns
- `xml_loader.go`: XML file parser for decoder and rule definitions

**Rule Engine:**
- `rule_model.go`: Rule data structures, pattern matching, compliance tags
- `rule_engine.go`: Rule evaluation logic, frequency correlation, condition chains

**Output & Integration:**
- `output.go`: JSON alert/archive formatting and file output
- `opensearch.go`: OpenSearch/Elasticsearch HTTP client with bulk indexing

**Configuration:**
- `watchflux.conf`: Runtime configuration file (ports, paths, OpenSearch settings)

**Ruleset:**
- `ruleset/decoders/`: XML files defining log format decoders for various vendors
- `ruleset/rules/`: XML files defining security rules and correlation logic

---

## Key Data Flows

### Complete Request Lifecycle

```
1. NETWORK LAYER
   ├─ UDP Reception (syslog_server.go:23)
   │  └─ Listens on configured UDP port (default: 5140)
   ├─ TCP Reception (syslog_server.go:48)
   │  └─ Accepts connections, reads newline-delimited logs
   └─ handleLog(raw, location) → Process Pipeline

2. PIPELINE ORCHESTRATION (pipeline.go:89)
   ├─ NewEvent(raw, location) → Create Event struct
   ├─ PreDecode(raw, event) → Phase 1
   ├─ RunDecoders(p.roots, event) → Phase 2
   └─ EvaluateRules(event, p.rules) → Phase 3

3. PHASE 1: PREDECODING (predecoder.go)
   ├─ Strip PRI header (<133> style)
   ├─ Parse RFC5424 (structured) or RFC3164 (legacy) envelope
   ├─ Extract: Timestamp, Hostname, ProgramName, Message
   └─ Extract key=value pairs → event.KVFields

4. PHASE 2: DECODING (decoder_tree.go)
   ├─ Match root decoders by prematch pattern
   ├─ Extract fields via regex named capture groups
   ├─ Route to event struct fields (srcip, dstip, action, etc.)
   ├─ Chain to child decoders if GetNext=true
   └─ Update event.DecoderFamily and event.DecoderName

5. PHASE 3: RULE EVALUATION (rule_engine.go)
   ├─ Evaluate all rules against decoded event
   ├─ Check 7-step condition chain:
   │  ├─ 1. Decoder family match
   │  ├─ 2. if_sid dependency chaining
   │  ├─ 3. Frequency correlation (sliding window)
   │  ├─ 4. Text pattern matching (match/regex)
   │  ├─ 5. Decoded field conditions (srcip, user, etc.)
   │  ├─ 6. Dynamic field conditions (<field name="x">)
   │  └─ 7. Standalone frequency checks
   └─ Collect matched rules → event.MatchedSIDs

6. OUTPUT GENERATION (output.go)
   ├─ Select highest-level rule for archive entry
   ├─ Write archive.json (every event)
   ├─ Write alerts.json (only matched rules, level>0)
   └─ Send to OpenSearch (if configured)
```

### Detailed Decoding Process

#### Decoder Tree Architecture

```
Root Decoders (Top-level log formats)
  │
  ├─ Variants (Alternative prematch patterns)
  │    ├─ Variant 1: Date format pattern A
  │    └─ Variant 2: Date format pattern B
  │
  └─ Child Decoders (Specific log types)
       ├─ "cisco-ios-login" (extends cisco-ios)
       ├─ "cisco-ios-logout" (extends cisco-ios)
       └─ "cisco-ios-acl" (extends cisco-ios)
```

#### Decoding Steps

**1. Root Decoder Selection:**
```go
for each root decoder:
    if program_name filter configured:
        check program_name match
    if prematch pattern(s) configured:
        try each variant's prematch
    if match found:
        proceed to regex extraction
```

**2. Regex Field Extraction:**
```go
// Two-pass regex matching for flexibility
if strict_regex matches:
    extract named capture groups
else if flex_regex matches:
    extract named capture groups (handles extra fields)
else:
    try next decoder
```

**3. Field Routing:**
```go
// Maps extracted values to event fields
extracted_fields.forEach((name, value) -> {
    value = strip_quotes(value)  // Remove surrounding quotes
    event.KVFields[name] = value  // Store for output
    switch(name) {
        case "srcip": event.SrcIP = value
        case "dstip": event.DstIP = value
        case "action": event.Action = value
        // ... more named fields
        default: event.DynFields[name] = value
    }
})
```

**4. Child Decoder Chaining:**
```go
if decoder.GetNext == true:
    continue to child decoders
    repeat steps 2-3 for each child
```

### Detailed Rule Correlation Process

#### Rule Matching Algorithm

**All rules are evaluated against every event** - this is not a decision tree but a pattern matching system where multiple rules can fire simultaneously.

```go
for each rule in rules:
    if matchRule(rule, event):
        event.MatchedSIDs.append(rule.ID)
        matched_rules.append(rule)
```

#### 7-Step Condition Chain

**Step 1: Decoder Family Check**
```go
if rule.DecodedAs != "":
    # Rule only matches specific decoder family
    if rule.DecodedAs != event.DecoderName &&
       rule.DecodedAs != event.DecoderFamily:
        return false
```
*Purpose:* Ensures SSH rules only match SSH logs, not Cisco logs

**Step 2: If_SID Chaining**
```go
if rule.IfSIDs not empty:
    # Rule fires only if another rule already matched this event
    for sid in rule.IfSIDs:
        if sid in event.MatchedSIDs:
            match_found = true
            break
    if not match_found:
        return false
```
*Purpose:* Enables rule composition - Rule B depends on Rule A

**Step 3: Frequency Correlation**
```go
if rule.IfMatchedSIDs not empty:
    # Check if referenced SID matched AND sliding window threshold reached
    if not sliding_window_check(rule.ID, rule.Frequency, rule.Timeframe):
        return false
```
*Purpose:* Time-based correlation across events (e.g., "5 failed logins in 60 seconds")

**Step 4: Text Pattern Matching**
```go
if not rule.Match.matches(event.Message):
    return false
if not rule.Regex.matches(event.Message):
    return false
```
*Purpose:* Match against raw message content

**Step 5: Decoded Field Conditions**
```go
if not rule.SrcIPPat.matches(event.SrcIP):
    return false
if not rule.DstIPPat.matches(event.DstIP):
    return false
if not rule.UserPat.matches(event.SrcUser):
    return false
# ... more field conditions
```
*Purpose:* Match against extracted structured fields

**Step 6: Dynamic Field Conditions**
```go
for field_rule in rule.FieldRules:
    value = event.GetField(field_rule.name)
    if not field_rule.pattern.matches(value):
        return false
```
*Purpose:* Match against any field (dynamic decoder fields like cisco.facility)

**Step 7: Standalone Frequency**
```go
if rule.Frequency > 0 and rule.IfMatchedSIDs empty:
    # Rule fires only after N hits (no dependency on other rules)
    if not sliding_window_check(rule.ID, rule.Frequency, rule.Timeframe):
        return false
```
*Purpose:* Self-contained frequency rule (e.g., "10 connections per minute")

#### Sliding Window Mechanism

```go
recordAndCheck(ruleID, threshold, timeframeSec, srcIP):
    # Track timestamps of matched events
    # Remove entries older than timeframe
    # Add current timestamp
    # Return true if count >= threshold

Example:
    Rule: "5 failed logins in 60 seconds"
    Events: [t=0, t=10, t=25, t=40, t=55] → count=5 → ALERT
    Next event at t=70: expires t=0 → count=4 → NO ALERT
```

### Rule Correlation Examples

**Example 1: Simple Field Match**
```xml
<rule id="1001" level="3">
    <decoded_as>cisco-ios</decoded_as>
    <field name="action">deny</field>
    <field name="cisco.facility">ACL</field>
    <description>Cisco ACL deny</description>
</rule>
```
**Flow:** Decoder check → Field matching

**Example 2: Frequency Correlation**
```xml
<rule id="1002" level="8" frequency="5" timeframe="60">
    <if_matched_sid>1001</if_matched_sid>
    <same_source_ip />
    <description>Multiple ACL denies from same IP</description>
</rule>
```
**Flow:** SID dependency → Sliding window → Same source IP filter

**Example 3: Multi-Condition Rule**
```xml
<rule id="1003" level="10">
    <decoded_as>sshd</decoded_as>
    <match>failed password</match>
    <field name="user">root</field>
    <srcip>!10.0.0.0/8</srcip>
    <description>Root login failure from external IP</description>
</rule>
```
**Flow:** Decoder check → Text match → User field → Negative IP pattern

**Example 4: Complex Correlation**
```xml
<rule id="1004" level="12" frequency="3" timeframe="120">
    <if_matched_sid>1003</if_matched_sid>
    <field name="action">login</field>
    <same_source_ip />
    <mitre>
        <id>T1110</id>
        <id>T1110.001</id>
    </mitre>
    <description>Multiple root login failures - Brute force attack</description>
</rule>
```
**Flow:** SID dependency → Frequency check → Field match → Same IP → MITRE tagging

---

## External Dependencies and Integrations

### Dependencies

**WatchFlux has zero external runtime dependencies.** It uses only the Go standard library:

| Package | Purpose |
|---------|---------|
| `net` | UDP/TCP networking |
| `encoding/xml` | XML decoder/rule parsing |
| `regexp` | Pattern matching and regex |
| `time` | Timestamp handling and sliding windows |
| `encoding/json` | JSON output formatting |
| `os`, `io`, `bufio` | File I/O and buffering |
| `flag` | Command-line argument parsing |
| `log` | Application logging |
| `sync` | Concurrency control for frequency tracking |
| `sync/atomic` | Thread-safe sequence numbering |

### Integrations

#### 1. Syslog Sources

**Supported Protocols:**
- **UDP Syslog (RFC3164)**: Fire-and-forget, ideal for high-volume sources
- **TCP Syslog (RFC3164/5424)**: Reliable delivery, connection-based

**Supported Log Sources:**
- Cisco IOS devices
- Fortigate firewalls (FOS5/6/7)
- SonicWall appliances
- Check Point Smart-1
- F5 BIG-IP
- SSH daemons
- Auditd (Linux)
- Sophos firewalls
- Any syslog-compatible device

#### 2. Output Destinations

**Local JSON Files:**
```json
// alerts.json - Only events that matched security rules
{
  "timestamp": "2026-03-21T13:45:32.000-0700",
  "rule": {
    "level": 10,
    "description": "Root login failure from external IP",
    "id": "1003",
    "firedtimes": 15,
    "mitre": ["T1110"]
  },
  "agent": {"name": "localhost", "id": "000"},
  "location": "192.168.1.100",
  "decoder": {"name": "sshd"},
  "data": {"user": "root", "srcip": "10.5.3.2"}
}

// archives.json - All processed events (with highest-level rule match)
{
  "timestamp": "2026-03-21T13:45:32.000-0700",
  "rule": { ... },  // Optional - present if rule matched
  "full_log": "Mar 21 13:45:32 sshd[1234]: Failed password for root from 10.5.3.2 port 22 ssh2",
  "decoder": {"name": "sshd"},
  "data": { ... }
}
```

**OpenSearch/Elasticsearch:**
```http
POST /watchflux-alerts-2026.03.21/_doc HTTP/1.1
Host: localhost:9200
Authorization: Basic YWRtaW46QmFuZ2xhZGVzaFNJRU0x

{
  "timestamp": "2026-03-21T13:45:32.000-0700",
  "rule": { ... },
  "agent": { ... },
  "location": "192.168.1.100",
  "decoder": { ... },
  "data": { ... }
}
```

**Features:**
- Daily index rotation (`watchflux-alerts-YYYY.MM.DD`)
- Bulk indexing for performance
- Basic authentication support
- Configurable index names
- Automatic index creation

#### 3. Wazuh/OSSEC Compatibility

WatchFlux supports the same XML formats as Wazuh and OSSEC:

**Decoder Format:**
```xml
<decoder name="ssh">
    <prematch>^ssh</prematch>
    <regex>^ssh\d?\[\d+\]: (?P<msg>.+)$</regex>
    <order>msg</order>
</decoder>
```

**Rule Format:**
```xml
<group name="authentication,authentication_failed">
  <rule id="5710" level="5">
    <if_sid>5700</if_sid>
    <match>invalid user|authentication failure|failed password</match>
    <description>SSHD: Attempt to login using a non-existent user</description>
    <group>authentication_failures</group>
    <mitre>
      <id>T1078</id>
      <id>T1078.004</id>
    </mitre>
  </rule>
</group>
```

#### 4. Configuration Files

**watchflux.conf:**
```ini
# Decoder directories
decoder_dir = ruleset/decoders

# Rule directories
rule_dir = ruleset/rules

# Syslog listeners
port = 5140        # UDP
tcp_port = 5141    # TCP

# Agent identity
agent = localhost.localdomain
agent_id = 000

# Output files
alerts_file = logs/alerts.json
archives_file = logs/archives.json

# OpenSearch (optional)
opensearch_url = http://127.0.0.1:9200
opensearch_username = admin
opensearch_password = BangladeshSIEM1
opensearch_alerts_index = watchflux-alerts
opensearch_archives_index = watchflux-archives
```

---

## Development Workflow

### Building

**From Source:**
```bash
# Ensure Go 1.22.2+ is installed
go version

# Build for current platform
go build -o watchflux

# Build for Linux AMD64 (cross-compile)
GOOS=linux GOARCH=amd64 go build -o watchflux-linux-amd64

# Build with optimizations
go build -ldflags="-s -w" -o watchflux
```

**Using Pre-built Binary:**
```bash
# The repository includes a pre-built Linux binary
./watchflux-linux-amd64
```

### Configuration

**1. Copy and Edit Configuration:**
```bash
# Use default configuration
cp watchflux.conf.example watchflux.conf

# Or create custom configuration
vim watchflux.conf
```

**2. Configure Decoders and Rules:**
```bash
# Add decoder XML files to ruleset/decoders/
cp my_decoder.xml ruleset/decoders/

# Add rule XML files to ruleset/rules/
cp my_rules.xml ruleset/rules/
```

**3. Configure Output Directories:**
```bash
# Create logs directory
mkdir -p logs

# Set permissions for output files
chmod 755 logs
```

### Running

**Production Mode:**
```bash
# Run with default configuration
./watchflux

# Run with custom configuration
./watchflux -config /path/to/custom.conf

# Run in background
./watchflux > /dev/null 2>&1 &

# Run with logging
./watchflux > logs/watchflux.log 2>&1 &
```

**Test Mode (Wazuh-logtest Compatibility):**
```bash
# Test a single log line
./watchflux -test 'Mar 21 13:45:32 sshd[1234]: Failed password for root from 10.5.3.2 port 22 ssh2'

# Output includes:
#   - Phase 1: Envelope parsing results
#   - Phase 2: Decoder match and extracted fields
#   - Phase 3: Rule matches with compliance tags
#   - Alert and archive file paths
```

**As a System Service (systemd):**

Create `/etc/systemd/system/watchflux.service`:
```ini
[Unit]
Description=WatchFlux SIEM Engine
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/watchflux
ExecStart=/opt/watchflux/watchflux
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable watchflux
sudo systemctl start watchflux
sudo systemctl status watchflux
```

### Testing

**1. Unit Testing (if present):**
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests for specific package
go test ./decoder_tree/
```

**2. Integration Testing with Real Logs:**
```bash
# Test with netcat (UDP)
echo '<34>Mar 21 13:45:32 sshd[1234]: Failed password for root from 10.5.3.2 port 22 ssh2' | nc -u localhost 5140

# Test with netcat (TCP)
echo '<34>Mar 21 13:45:32 sshd[1234]: Failed password for root from 10.5.3.2 port 22 ssh2' | nc localhost 5141

# Check alerts output
tail -f logs/alerts.json

# Check archives output
tail -f logs/archives.json
```

**3. Testing with Log Sources:**

**Configure rsyslog to forward to WatchFlux:**
```bash
# Add to /etc/rsyslog.conf
*.* @@127.0.0.1:5141

# Restart rsyslog
sudo systemctl restart rsyslog
```

**Configure syslog-ng to forward to WatchFlux:**
```bash
# Add to syslog-ng.conf
destination d_watchflux {
    tcp("127.0.0.1" port(5141));
};

log {
    source(s_src);
    destination(d_watchflux);
};
```

**4. Testing Rule Development:**

Use test mode for rapid rule development:
```bash
# Test decoder matching
./watchflux -test 'Mar 21 13:45:32 myapp[123]: user=admin action=login status=success ip=192.168.1.1'

# Expected output shows:
# - Which decoder matched
# - What fields were extracted
# - Which rules matched
# - Compliance tags (PCI, GDPR, etc.)
```

### Monitoring and Debugging

**1. Application Logs:**
```bash
# Standard output shows:
# - Initialization status
# - Rule loading counts
# - Decoder tree structure
# - Ingest statistics
# - Alert generation

# Run with output visible
./watchflux

# Or redirect to file
./watchflux > logs/watchflux.log 2>&1 &
tail -f logs/watchflux.log
```

**2. Alert Monitoring:**
```bash
# Watch alerts in real-time
tail -f logs/alerts.json | jq .

# Watch all events
tail -f logs/archives.json | jq .
```

**3. OpenSearch Queries:**
```bash
# Query recent alerts
curl -X GET "localhost:9200/watchflux-alerts-2026.03.21/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match_all": {}
  },
  "size": 10,
  "sort": [
    {"timestamp": {"order": "desc"}}
  ]
}'

# Query critical alerts
curl -X GET "localhost:9200/watchflux-alerts-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "rule.level": {
        "gte": 10
      }
    }
  }
}'
```

**4. Performance Monitoring:**
```bash
# Check process resources
ps aux | grep watchflux

# Monitor network connections
netstat -an | grep 5140  # UDP
netstat -an | grep 5141  # TCP

# Monitor disk usage for logs
df -h logs/
du -sh logs/*
```

### Deployment

**1. Simple Deployment (Single Node):**
```bash
# Copy binary to target server
scp watchflux-linux-amd64 user@server:/opt/watchflux/watchflux

# Copy configuration
scp watchflux.conf user@server:/opt/watchflux/

# Copy ruleset
scp -r ruleset user@server:/opt/watchflux/

# SSH to server
ssh user@server

# Create logs directory
mkdir -p /opt/watchflux/logs

# Set permissions
chmod +x /opt/watchflux/watchflux
chmod 755 /opt/watchflux/logs

# Start service
sudo systemctl start watchflux
```

**2. Production Deployment:**

**Considerations:**
- **Port Requirements**: UDP/TCP 514 (requires root) or non-privileged ports (>1024)
- **Disk Space**: Plan for logs growth (archive all events, alerts only for matches)
- **Network**: Ensure syslog sources can reach the server
- **OpenSearch**: Deploy OpenSearch cluster for production workloads
- **Monitoring**: Set up monitoring for the WatchFlux process
- **Backups**: Backup configuration and ruleset files

**Deployment Checklist:**
- [ ] Go 1.22.2+ installed (or use pre-built binary)
- [ ] Configuration file configured
- [ ] Decoder files tested and validated
- [ ] Rule files tested and validated
- [ ] Output directories created with correct permissions
- [ ] OpenSearch configured (if using)
- [ ] Firewall rules allow syslog input
- [ ] Systemd service configured
- [ ] Monitoring and logging configured
- [ ] Backup strategy in place

**3. Docker Deployment (optional):**

Create `Dockerfile`:
```dockerfile
FROM golang:1.22.2-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o watchflux

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/watchflux .
COPY --from=builder /app/watchflux.conf .
COPY --from=builder /app/ruleset ./ruleset
RUN mkdir -p logs
EXPOSE 5140/udp 5141/tcp
CMD ["./watchflux"]
```

Build and run:
```bash
docker build -t watchflux .
docker run -d -p 5140:5140/udp -p 5141:5141 watchflux
```

### Maintenance

**1. Log Rotation:**
```bash
# Configure logrotate
cat > /etc/logrotate.d/watchflux << EOF
/opt/watchflux/logs/*.json {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 watchflux watchflux
}
EOF

# Test logrotate
logrotate -f /etc/logrotate.d/watchflux
```

**2. Configuration Updates:**
```bash
# Edit configuration
vim /opt/watchflux/watchflux.conf

# Restart service to apply changes
sudo systemctl restart watchflux
# or send SIGHUP for hot reload (if implemented)
sudo systemctl reload watchflux
```

**3. Decoder/Rule Updates:**
```bash
# Update decoders
scp new_decoders.xml user@server:/opt/watchflux/ruleset/decoders/

# Update rules
scp new_rules.xml user@server:/opt/watchflux/ruleset/rules/

# Restart service
sudo systemctl restart watchflux
```

**4. Upgrading:**
```bash
# Stop service
sudo systemctl stop watchflux

# Backup current installation
cp -r /opt/watchflux /opt/watchflux.backup

# Deploy new binary
scp watchflux-linux-amd64 user@server:/opt/watchflux/watchflux

# Start service
sudo systemctl start watchflux

# Verify operation
sudo systemctl status watchflux
tail -f /opt/watchflux/logs/watchflux.log
```

---

## Performance Considerations

### Scalability

**Single Node Capacity:**
- **Events/second**: 10,000+ (depending on rule complexity)
- **Throughput**: ~100 MB/s (compressed syslog)
- **Memory**: 50-200 MB (depends on decoder/rule count)

**Scaling Options:**
1. **Horizontal Scaling**: Deploy multiple instances with load balancer
2. **Vertical Scaling**: Increase CPU cores and memory
3. **Batch Processing**: Use OpenSearch bulk indexing

### Optimization Tips

**1. Decoder Optimization:**
- Place most specific decoders first in parent-child chains
- Use prematch patterns to reduce regex attempts
- Avoid overly complex regex patterns

**2. Rule Optimization:**
- Use `decoded_as` to filter rules early
- Place high-frequency rules before low-frequency rules
- Use `if_sid` chaining to avoid redundant evaluations

**3. Network Optimization:**
- Use UDP for high-volume, low-importance logs
- Use TCP for critical logs requiring reliable delivery
- Consider syslog message compression

**4. Output Optimization:**
- Use OpenSearch for large-scale deployments
- Batch writes to reduce I/O overhead
- Configure appropriate retention policies

---

## Troubleshooting

### Common Issues

**1. Port Binding Errors:**
```
ERROR: bind UDP :514: bind: permission denied
```
**Solution:** Use non-privileged port (>1024) or run as root:
```bash
sudo ./watchflux
# or configure port=5140 in watchflux.conf
```

**2. Decoder Not Matching:**
```
[recv] 192.168.1.100 NO_DECODER Mar 21...
```
**Solution:**
- Check decoder XML syntax: `xmllint --noout decoder.xml`
- Verify prematch pattern matches log format
- Use test mode: `./watchflux -test 'your_log_here'`

**3. Rules Not Firing:**
```
[recv] ... NO_DECODER ... (no rules matched)
```
**Solution:**
- Verify decoder matched first
- Check rule conditions (decoded_as, match, field)
- Use test mode to debug rule matching
- Check frequency thresholds

**4. OpenSearch Connection Errors:**
```
ERROR: OpenSearch connection failed: dial tcp 127.0.0.1:9200: connect: connection refused
```
**Solution:**
- Verify OpenSearch is running: `curl http://localhost:9200`
- Check URL configuration in watchflux.conf
- Verify network connectivity and firewall rules

**5. High Memory Usage:**
**Solution:**
- Reduce number of loaded decoders/rules
- Check for frequency tracking accumulation
- Monitor memory with `ps aux | grep watchflux`

### Debug Mode

**Enable verbose logging:**
```bash
# The application logs initialization details to stdout
./watchflux 2>&1 | tee debug.log

# Look for:
# - Decoder loading: [init] decoder file ... → N decoders
# - Rule loading: [init] rule file ... → N rules
# - Decoder tree: [init] decoder tree: N root(s), N total
# - Total rules: [init] total rules: N
```

**Test mode debugging:**
```bash
# Test specific log lines
./watchflux -test 'your_log_here'

# The output shows:
# - Phase 1: Envelope parsing results
# - Phase 2: Decoder match and extracted fields
# - Phase 3: Rule matches with compliance tags
# - Output file paths
```

---

## Conclusion

WatchFlux provides a lightweight, efficient SIEM engine with zero external dependencies. Its modular architecture separates concerns clearly:

- **Network Layer**: Syslog reception via UDP/TCP
- **Decoding Layer**: Hierarchical decoder trees for log parsing
- **Correlation Layer**: Rule engine with advanced correlation features
- **Output Layer**: JSON files and OpenSearch integration

The system is designed for simplicity, performance, and Wazuh/OSSEC compatibility, making it suitable for both development and production environments.

For more information, refer to:
- Source code comments in each module
- Example decoder files in `ruleset/decoders/`
- Example rule files in `ruleset/rules/`
- Configuration template in `watchflux.conf`
