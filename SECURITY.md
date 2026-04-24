# Security & Threat Model — Cybersicker

> **STRIDE Threat Model + Cybersecurity Skills Integration**  
> Version: 2.0 | Integration with 754-skill Anthropic Cybersecurity Library

---

## Executive Summary

Cybersicker is an **agentic AI SOC system** for IoT threat detection. This document maps:
1. **STRIDE threat model** per component
2. **754 cybersecurity skills** to detection capabilities
3. **Framework compliance**: MITRE ATT&CK, NIST CSF 2.0, NIST AI RMF

---

## 🏗️ System Architecture & Security Perimeter

```
┌────────────────────────────────────────────────────────────┐
│  🔒 Security Perimeter: Cybersicker IoT SOC System         │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  1️⃣  Threat Input Layer                                     │
│  ├─ Network traffic logs (CSV/streaming)               │
│  ├─ External APIs (VirusTotal, NIST NVD)               │
│  └─ User chat input (Streamlit + CLI)                  │
│                                                             │
│  2️⃣  Processing Layer                                       │
│  ├─ autoencoder.py (ML anomaly detection)              │
│  ├─ agent.py (LangChain orchestrator)                  │
│  ├─ playbook.env.txt (RAG knowledge base)              │
│  └─ Tool definitions (VirusTotal, NIST, MAC lookup)    │
│                                                             │
│  3️⃣  Output Layer                                           │
│  ├─ Streamlit dashboard (app.py)                       │
│  ├─ CLI terminal (agent.py)                            │
│  └─ JSON/PDF reports                                       │
│                                                             │
│  4️⃣  External Dependencies                                  │
│  ├─ Google Gemini 2.5 Flash (LLM)                      │
│  ├─ VirusTotal API                                         │
│  ├─ NIST NVD API                                           │
│  └─ macvendors.com API                                     │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

---

## 🎯 STRIDE Threat Model by Component

### Component 1: autoencoder.py — ML Anomaly Detection

#### Spoofing (S) — False Threat Signals

**Threats:**
- Attacker crafts network logs mimicking legitimate traffic to trigger false alarms
- Poisoned training data during model retraining
- Replayed old logs to create ghost alerts

**Cybersecurity Skills:**
- `data-poisoning-attack-defense` (MITRE ATLAS, Malware Analysis)
- `network-traffic-analysis-fundamentals` (Network Security)
- `detecting-replay-attacks` (Incident Response)

**Mitigation:**
- Validate training data source & integrity checksums
- Cross-reference anomaly scores with behavioral indicators
- Implement feature randomization per batch (anti-adversarial)
- Skip alerts if timestamp is outside valid range

#### Tampering (T) — Model Manipulation

**Threats:**
- Adversarial inputs designed to evade autoencoder
- Model weight extraction via side-channel attacks
- Gradient-based attacks to craft undetectable malware traffic

**Cybersecurity Skills:**
- `adversarial-ml-attack-defense` (MITRE ATLAS)
- `model-extraction-attacks-defense` (MITRE ATLAS)
- `deep-learning-evasion-techniques` (Malware Analysis)

**Mitigation:**
- Add defensive randomization (dropout at inference)
- Monitor reconstruction error variance for anomalies
- Use ensemble detection (autoencoder + rule-based + behavioral)
- Implement model versioning & rollback
- STRIDE audit: Run `/cso` before shipping ML model updates

#### Repudiation (R) — Deniability of Actions

**Threats:**
- Attacker disputes alert authenticity
- System fails to audit trail alert generation
- Log tampering to hide detection evidence

**Cybersecurity Skills:**
- `network-log-integrity` (Network Security)
- `forensic-logging-procedures` (Digital Forensics)
- `immutable-audit-logging` (Incident Response)

**Mitigation:**
- Cryptographically sign anomaly scores (timestamp + model version)
- Write alerts to append-only log stream
- Store MSE calculations with feature vector snapshot
- Trace: autoencoder version → training dataset → alert timestamp

**Implementation:**
```python
import hashlib
from datetime import datetime

def log_anomaly_with_integrity(
    mse_score: float, 
    features: list, 
    model_version: str
):
    """Log anomaly with cryptographic integrity."""
    timestamp = datetime.utcnow().isoformat()
    entry = f"{timestamp}|{mse_score}|{model_version}|{len(features)}"
    checksum = hashlib.sha256(entry.encode()).hexdigest()
    log_immutable_stream(f"{entry}|{checksum}")
```

#### Information Disclosure (I) — Data Leakage

**Threats:**
- Feature vectors contain sensitive information (IP addresses, MAC addresses)
- Reconstruction outputs expose private traffic patterns
- Model explains confidential network topology

**Cybersecurity Skills:**
- `data-classification-identification` (Compliance & Governance)
- `pii-detection-masking` (Cloud Security)
- `output-data-sanitization` (Incident Response)

**Mitigation:**
- Strip PII from reconstructed logs before storage
- Mask IP/MAC in public dashboards (last octet only)
- Use differential privacy: add noise to MSE scores (±1%)
- Store full logs in encrypted, access-controlled vault

#### Denial of Service (D) — System Unavailability

**Threats:**
- Million-record log causes autoencoder to hang
- GPU memory exhaustion during inference
- Slowdown attacks on model training

**Cybersecurity Skills:**
- `resource-exhaustion-defense` (Network Security)
- `ddos-mitigation-strategies` (Incident Response)
- `model-performance-scaling` (Malware Analysis)

**Mitigation:**
- Batch size limits (max 10K records per inference)
- GPU memory caps (soft limits with spillover to CPU)
- Async processing with timeout (30s max per batch)
- Rate limit: 1 training cycle per day

#### Elevation of Privilege (E) — Unauthorized Access

**Threats:**
- Model inference code runs as root, allowing RCE
- Pickle deserialization exploits load untrusted model files
- Python subprocess calls inject shell commands

**Cybersecurity Skills:**
- `python-security-vulnerabilities` (Security Operations)
- `privilege-escalation-detection` (Incident Response)
- `secure-coding-principles` (DevSecOps)

**Mitigation:**
- Run autoencoder in sandboxed container (non-root user)
- Use `joblib` or HDF5 instead of pickle for model serialization
- No subprocess calls—use TensorFlow operations only
- Validate model signatures (SHA256) before loading

---

### Component 2: agent.py — LangChain Agent Orchestrator

#### Spoofing (S) — False Agent Identity / Fake Tool Responses

**Threats:**
- Attacker impersonates VirusTotal API, returns false positives
- Malicious MAC vendor database returns spoofed device info
- Agent pranked into trusting unverified threat intelligence

**Cybersecurity Skills:**
- `threat-intel-data-validation` (Threat Intelligence)
- `api-response-verification` (Cloud Security)
- `ssl-tls-certificate-validation` (Network Security)

**Mitigation:**
- Verify HTTPS certificates (no --insecure flag)
- Validate API response signatures (if available)
- Check VirusTotal positivity rate across vendors (consensus threshold)
- Implement circuit breaker (disable API if >30% error rate)

#### Tampering (T) — Tool Response Manipulation / Prompt Injection

**Threats:**
- Malicious website injects instructions into agent via tool scraping
- VirusTotal returns crafted JSON that changes agent behavior
- Agent prompt injection via user input ("ignore system prompt")

**Cybersecurity Skills:**
- `prompt-injection-defense-ai` (AI Risk Management, NIST AI RMF)
- `llm-security-vulnerabilities` (Security Operations)
- `json-deserialization-attacks` (Web Application Security)

**Mitigation:**
- Sanitize all tool responses before feeding to LLM
- Use strict schema validation (pydantic models for API responses)
- Bounded agent iterations (max 5 tool calls per user prompt)
- Append `[End of Tool Response]` marker to all tool outputs
- Implement prompt template guards (no user input in system prompt)

**Implementation:**
```python
from pydantic import BaseModel, ValidationError

class VirusTotalResponse(BaseModel):
    """Strict schema for VirusTotal API responses."""
    ip: str
    reputation: int  # 0-100
    threat_types: list[str]  # e.g., ["trojan", "botnet"]
    
@tool
def check_ip_reputation(ip: str) -> str:
    """Check IP reputation (sanitized response)."""
    try:
        response = virustotal.client.get(ip)
        validated = VirusTotalResponse(**response)
        return f"[Tool Response] IP {validated.ip}: {validated.reputation}/100"
    except ValidationError as e:
        logger.warning(f"Invalid API response: {e}")
        return "[Tool Error] Could not verify IP reputation"
```

#### Repudiation (R) — Agent Denies Its Actions

**Threats:**
- Agent claims it didn't make a threat determination (no audit trail)
- Chat history lost after session crash
- No record of which model version made decisions

**Cybersecurity Skills:**
- `session-logging-procedures` (Security Operations)
- `incident-response-documentation` (Incident Response)
- `evidence-preservation` (Digital Forensics)

**Mitigation:**
- Log every agent tool call (timestamp, tool name, input, output)
- Store chat history in encrypted session database
- Include model version in every alert: `Alert Generated: Gemini 2.5 Flash v1.2`
- Append-only logs with cryptographic chain

#### Information Disclosure (I) — Sensitive Data in Logs

**Threats:**
- Agent chat history exposes customer's internal IP ranges
- Tool responses reveal device names, firmware versions of victim network
- Logs stored unencrypted on disk accessible to other processes

**Cybersecurity Skills:**
- `data-at-rest-encryption` (Cloud Security)
- `data-in-transit-encryption` (Network Security)
- `log-sanitization-pii-removal` (Compliance & Governance)

**Mitigation:**
- Encrypt session database with AES-256-GCM
- Mask internal IPs in logs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 → INTERNAL)
- Mask MAC addresses (keep vendor prefix, redact device ID)
- Separate chat history (user-facing) from internal logs (encrypted)

#### Denial of Service (D) — Agent Becomes Unavailable

**Threats:**
- User asks agent to process 1M domain names → timeout
- Recursive tool calls cause stack overflow (tool → agent → tool → ...)
- API rate limits hit during spike attack monitoring

**Cybersecurity Skills:**
- `rate-limiting-api-protection` (API Security)
- `resource-bounded-optimization` (Cloud Security)
- `retry-logic-exponential-backoff` (DevSecOps)

**Mitigation:**
- Max 100 records per tool call (fail-safe)
- Max 5 tool invocations per user prompt (circuit breaker)
- API rate limit headers respected (429 → exponential backoff)
- Separate thread pool for agent (don't block main Streamlit thread)

**Implementation:**
```python
from functools import wraps
from ratelimit import limits, sleep_and_retry

@sleep_and_retry
@limits(calls=10, period=60)  # 10 API calls per minute
def query_virustotal_api(ip: str) -> dict:
    """Rate-limited VirusTotal API calls."""
    return virustotal_client.get(ip)

# In agent tool:
@tool
def check_ip_reputation(ip: str) -> str:
    """Check IP reputation (rate-limited)."""
    try:
        result = query_virustotal_api(ip)
        return format_response(result)
    except RateLimitException:
        return "[Rate Limited] Please try again in 60 seconds"
```

#### Elevation of Privilege (E) — Agent Gains Excessive Permissions

**Threats:**
- Agent can modify detection rules or thresholds via tool calls
- SQL injection in tool calls to query CVE database
- Agent tricks tool into executing arbitrary code

**Cybersecurity Skills:**
- `access-control-enforcement` (Identity & Access Management)
- `sql-injection-prevention` (Web Application Security)
- `command-injection-defense` (Security Operations)

**Mitigation:**
- Tools are read-only (queries only, no writes to thresholds/rules)
- All database queries use parameterized statements
- No shell execution—use library APIs instead
- Run agent with minimal required permissions

---

### Component 3: playbook.env.txt — Incident Response Knowledge Base

#### Spoofing (S) — Fake Playbooks / Outdated Procedures

**Threats:**
- Attacker sneaks malicious incident response steps into playbook
- Outdated playbook references deprecated tools/APIs
- Playbook recommends dangerous remediation steps

**Cybersecurity Skills:**
- `playbook-validation-testing` (Incident Response)
- `procedure-currency-maintenance` (Security Operations)
- `risk-assessment-remediation` (Compliance & Governance)

**Mitigation:**
- Version playbook: `playbook-v2.0-timestamp.txt`
- Review playbook quarterly with SOC team
- Cross-reference procedures with official incident response standards (NIST 800-61)
- Tag deprecated steps: `[DEPRECATED - Use X instead]`
- Use `/document-release` gstack skill to auto-update playbooks

#### Tampering (T) — Unauthorized Playbook Edits

**Threats:**
- Attacker modifies playbook.env.txt to recommend risky actions
- Without version control, tampering is undetectable

**Cybersecurity Skills:**
- `version-control-integrity` (DevSecOps)
- `access-control-file-permissions` (Security Operations)

**Mitigation:**
- Store playbook in git (immutable history)
- Require pull request + peer review for changes
- Sign playbook releases (GPG signature)
- File permissions: 644 (read-only for agent, edit by authorized users only)

#### Repudiation (R) — Playbook Origin Unknown

**Threats:**
- Agent claims it followed the "official" playbook but can't prove it
- Playbook version used for incident not recorded

**Cybersecurity Skills:**
- `audit-trail-completeness` (Security Operations)
- `evidence-chain-of-custody` (Digital Forensics)

**Mitigation:**
- Log: `Incident Response Step: [playbook-v2.0] Step #3: Isolate subnet 10.0.1.0/24`
- Include playbook SHA256 hash in incident report
- Maintain playbook manifest: `playbook-v2.0 @ 2026-04-24 (hash: abc123...)`

#### Information Disclosure (I) — Sensitive IPs/Credentials in Playbook

**Threats:**
- Playbook contains example IPs, credentials, or network topology
- Stored in unencrypted repo

**Cybersecurity Skills:**
- `secret-scanning-detection` (DevSecOps)
- `hardcoded-credential-prevention` (Secure Coding)

**Mitigation:**
- All example IPs use RFC 5737 ranges: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
- No credentials in playbook (use credential store / secrets manager)
- Scan playbook with `git-secrets` or `truffleHog` before commit
- Playbook.env.txt file permissions: mode 600 (read-only by agent user)

#### Denial of Service (D) — Massive Playbook / RAG Timeout

**Threats:**
- Playbook has 100K procedures → ChromaDB takes 10s to search
- Agent loops through playbook endlessly looking for edge case

**Cybersecurity Skills:**
- `knowledge-base-optimization` (Threat Intelligence)
- `search-performance-tuning` (Security Operations)

**Mitigation:**
- Limit playbook size: <50 MB
- ChromaDB search timeout: 5 seconds strict
- Cache recent playbook lookups (LRU cache, 100 entries)
- Playbook index: by threat type (botnet, ransomware, ddos) for fast lookup

#### Elevation of Privilege (E) — Playbook Recommends Risky Actions

**Threats:**
- Playbook says "Log in as root to check file integrity" → RCE risk
- Recommends disabling security controls during incident (firewall off)

**Cybersecurity Skills:**
- `incident-response-best-practices` (Incident Response, NIST 800-61)
- `least-privilege-incident-response` (Identity & Access Management)

**Mitigation:**
- Playbook review checklist: "Does this require root? If yes, explain why."
- Principle of least privilege: Document minimum permissions needed for each step
- Flag high-risk steps: `[⚠️ HIGH RISK] Disable firewall only if isolated network`
- Manual approval required for steps marked HIGH RISK

---

### Component 4: app.py — Streamlit SOC Dashboard

#### Spoofing (S) — Dashboard Shows False Data / Attackers Impersonate SOC

**Threats:**
- Man-in-the-middle intercepts Streamlit traffic
- Attacker forges threat alerts to confuse SOC analyst
- Dashboard displays results from untrusted agent

**Cybersecurity Skills:**
- `session-hijacking-prevention` (Identity & Access Management)
- `web-application-security-headers` (Web Application Security)
- `tls-certificate-pinning` (Network Security)

**Mitigation:**
- HTTPS only (TLS 1.3+)
- Set `Strict-Transport-Security: max-age=31536000` header
- Session tokens: short-lived (5 min), signed with secrets
- Display alert source: `[Agent: Gemini 2.5 Flash v1.2 @ 2026-04-24 15:32:20 UTC]`

#### Tampering (T) — XSS / Code Injection in Dashboard

**Threats:**
- Attacker injects JavaScript in threat report
- HTML rendering of untrusted data allows DOM-based XSS
- CSV/JSON export contains executable code

**Cybersecurity Skills:**
- `xss-prevention-owasp-top-10` (Web Application Security)
- `output-encoding-sanitization` (Secure Coding)
- `csp-content-security-policy` (Web Application Security)

**Mitigation:**
- Use `st.markdown(..., unsafe_allow_html=False)` (default safe)
- Escape all user/agent output: `html.escape(text)`
- Set Content-Security-Policy header (no inline scripts)
- Validate JSON structure before rendering
- CSV download: use pandas CSV writer (safe encoding)

**Implementation:**
```python
import streamlit as st
import html

def display_threat_alert(alert_dict: dict):
    """Display threat alert with XSS protection."""
    threat_type = html.escape(alert_dict["threat_type"])  # e.g., "botnet"
    ip = html.escape(alert_dict["ip"])                      # e.g., "192.0.2.1"
    description = html.escape(alert_dict["description"])    # Free text
    
    # Safe to render now
    st.warning(f"🚨 Threat: {threat_type} from {ip}\n{description}")
```

#### Repudiation (R) — Dashboard Actions Unlogged

**Threats:**
- SOC analyst claims they didn't export sensitive alert data
- No audit trail of who viewed which alerts

**Cybersecurity Skills:**
- `web-access-logging` (Security Operations)
- `user-action-auditing` (Compliance & Governance)

**Mitigation:**
- Log every action: view alert, export CSV, run detection, export report
- Include user ID, timestamp, IP address, action type
- Rotation: daily logs (encrypted), retention 90 days

#### Information Disclosure (I) — Sensitive Data in Browser / Cache

**Threats:**
- Browser cache stores threat reports with PII
- CDN logs contain unmasked threat data
- Mouse-over tooltips expose detailed threat indicators

**Cybersecurity Skills:**
- `browser-cache-control` (Web Application Security)
- `data-classification-pii-handling` (Cloud Security)

**Mitigation:**
- Set cache headers: `Cache-Control: no-store, no-cache, must-revalidate`
- Mask sensitive data on dashboard (IPs, MACs → last octets only)
- Tooltips show summary only; details require explicit click
- Secure cookies: `secure=True, httponly=True, samesite=Strict`

**Implementation:**
```python
def mask_ip(ip: str) -> str:
    """Mask IP address for dashboard display."""
    octets = ip.split('.')
    if len(octets) == 4:
        return f"{octets[0]}.{octets[1]}.{octets[2]}.***"
    return ip  # Fallback

def create_threat_card(threat: dict) -> None:
    """Create threat card with masked data."""
    st.metric(
        label="Source IP",
        value=mask_ip(threat["ip"]),
        delta="High Threat"
    )
```

#### Denial of Service (D) — Dashboard Becomes Unresponsive

**Threats:**
- Display 1M alerts → browser hangs
- Large dataset render causes Streamlit to slow down
- Attacker crafts expensive queries (sort, filter on massive dataset)

**Cybersecurity Skills:**
- `frontend-performance-optimization` (Web Application Security)
- `rendering-performance-limits` (DevSecOps)

**Mitigation:**
- Paginate alerts (show 50 per page)
- Lazy load: detect scroll, load next batch
- Server-side filtering/sorting (don't send all data to browser)
- Debounce search input (min 3 chars, wait 500ms before search)

#### Elevation of Privilege (E) — Dashboard Allows Unauthorized Actions

**Threats:**
- Unauthenticated user accesses dashboard
- Dashboard allows disabling detection rules without authorization
- User can modify incident response procedures via dashboard

**Cybersecurity Skills:**
- `authentication-enforcement` (Identity & Access Management)
- `authorization-access-control` (Security Operations)
- `role-based-access-control-rbac` (Compliance & Governance)

**Mitigation:**
- Require login (OAuth2 / API key)
- RBAC: analyst (read-only), manager (update thresholds), admin (code changes)
- Detection rules: read-only via dashboard
- Incident response procedures: view-only; edits via git pull request only
- All privilege changes logged and audited

---

## 🎯 Cybersecurity Skills Mapping to Components

### Critical Skills (Must Have)

| Skill | Domain | Component | Use Case |
|-------|--------|-----------|----------|
| `network-traffic-analysis-fundamentals` | Network Security | autoencoder.py | Feature selection, anomaly definition |
| `prompt-injection-defense-ai` | AI Risk Management | agent.py | LLM security hardening |
| `threat-intel-data-validation` | Threat Intelligence | agent.py tools | API response verification |
| `ransomware-incident-response-playbook` | Incident Response | playbook.env.txt | Containment procedures |
| `ddos-mitigation-strategies` | Network Security | autoencoder.py, agent.py | Detection + response |
| `xss-prevention-owasp-top-10` | Web App Security | app.py | Dashboard safety |
| `data-classification-identification` | Compliance & Governance | All | PII / sensitive data handling |

### High-Priority Skills (Strongly Recommended)

| Skill | Domain | Component | Use Case |
|-------|--------|-----------|----------|
| `detecting-botnet-traffic-patterns` | Threat Hunting | autoencoder.py | C2 detection |
| `detecting-lateral-movement-in-networks` | Threat Hunting | autoencoder.py | Internal reconnaissance |
| `malware-analysis-fundamentals` | Malware Analysis | agent.py playbook | Behavior-based detection |
| `incident-response-playbook-structure` | Incident Response | playbook.env.txt | Procedure organization |
| `iot-device-discovery-scanning` | IoT Security | agent.py MAC tool | Device inventory |
| `cvss-score-interpretation` | Vulnerability Management | agent.py CVE tool | Severity scoring |
| `ssl-tls-certificate-validation` | Network Security | app.py agent.py | HTTPS verification |

### Medium-Priority Skills (Nice to Have)

| Skill | Domain | Component | Use Case |
|-------|--------|-----------|----------|
| `threat-hunting-hypothesis-generation` | Threat Hunting | agent.py | Hypothesis-driven queries |
| `cloud-security-aws-azure-gcp-hardening` | Cloud Security | (if deployed on cloud) | Infrastructure security |
| `security-logging-best-practices` | Security Operations | All | Audit trail implementation |
| `penetration-testing-methodology` | Penetration Testing | (testing phase) | Validate detection rules |

---

## 📋 Security Compliance Mapping

### MITRE ATT&CK Framework Coverage

**Current Detection Capability:**

| Tactic | Technique | Detection Method | Cybersecurity Skill |
|--------|-----------|------------------|-------------------|
| **Reconnaissance** | T1595: Active Scanning | Port scan pattern detection | `network-port-scanning-detection` |
| **Resource Dev.** | T1583: Acquire Infrastructure | C2 domain lookup | `command-control-infrastructure` |
| **Initial Access** | T1566: Phishing | Email traffic anomalies | `phishing-traffic-detection` |
| **Execution** | T1204: User Execution | Suspicious script execution | `script-execution-anomaly` |
| **Persistence** | T1547: Boot/Logon Autostart | Persistence mechanism detection | `persistence-technique-detection` |
| **Privilege Escalation** | T1548: Abuse Elevation Control | Privilege grant anomalies | `privilege-escalation-indicator` |
| **Defense Evasion** | T1140: Deobfuscation | Encryption/encoding patterns | `encryption-anomaly-detection` |
| **Credential Access** | T1555: Credentials from Password Store | LSASS/SAM access | `credential-dumping-detection` |
| **Discovery** | T1580: Cloud Infrastructure Discovery | Cloud API reconnaissance | `cloud-api-scan-detection` |
| **Lateral Movement** | T1570: Lateral Tool Transfer | Internal tool propagation | `internal-tool-transfer-detection` |
| **Collection** | T1557: Man-in-the-Middle | Traffic interception patterns | `mitm-attack-detection` |
| **Exfiltration** | T1041: Exfiltration Over C2 | Large data transfer anomalies | `data-exfil-pattern-detection` |
| **Command & Control** | T1008: Fallback Channels | C2 communication switching | `c2-fallback-detection` |
| **Impact** | T1531: Account Access Removal | Privilege revocation | `privilege-removal-detection` |

### NIST CSF 2.0 Alignment

| NIST CSF Function | Category | Cybersicker Implementation |
|-------------------|----------|--------------------------|
| **GOVERN** | GV.RO: Risk & Oversight | Risk scoring, alert prioritization |
| | GV.OC: Organizational Context | IoT asset inventory (MAC lookup) |
| **PROTECT** | PR.AT: Awareness & Training | Incident response playbook |
| | PR.AC: Access Control | Agent authorization (RBAC dashboard) |
| | PR.DS: Data Security | Log encryption, PII masking |
| | PR.PT: Protective Tech | Network segmentation recommendations |
| **DETECT** | DE.AE: Anomalies & Events | Autoencoder anomaly scoring |
| | DE.CM: Security Monitoring | Real-time threat detection |
| | DE.DP: Detection Processes | Agent-driven investigation |
| **RESPOND** | RS.RP: Response Planning | Playbook execution |
| | RS.CO: Communications | Team escalation workflows |
| | RS.AN: Analysis | Forensic data collection |
| **RECOVER** | RC.RP: Recovery Planning | Playbook recovery procedures |
| | RC.IM: Improvements | Incident lessons learned |

### NIST AI RMF (AI Risk Management)

| AI RMF Function | Cybersicker Implementation | Skill Reference |
|-----------------|---------------------------|-----------------|
| **MEASURE** | Measure model accuracy, false positive rate | `ml-model-evaluation-metrics` |
| | Measure adversarial robustness | `adversarial-ml-attack-defense` |
| | Measure AI transparency | `model-explainability-interpretability` |
| **MANAGE** | Manage ML model drift | `model-drift-detection-retraining` |
| | Manage prompt injection risks | `prompt-injection-defense-ai` |
| | Manage data quality | `data-poisoning-attack-defense` |
| **MAP** | Map AI components to MITRE ATT&CK | (This document) |
| | Map detection capabilities | Threat Hunt techniques in skills |
| **GOVERN** | Governance of AI decision-making | CLAUDE.md + `/cso` security reviews |

---

## 🔐 Security Checklist Before Production Deployment

Use gstack `/cso` skill and this checklist:

- [ ] **STRIDE Model**: Every component reviewed against STRIDE threats
- [ ] **Threat Intelligence APIs**: TLS certificate validation, rate limiting, input validation
- [ ] **LLM Agent**: Prompt injection defense, tool call limitations, response sanitization
- [ ] **ML Model**: Adversarial robustness testing, data integrity validation, model versioning
- [ ] **Database**: Encryption at rest (AES-256), encryption in transit (TLS 1.3)
- [ ] **Logs & Audit**: Immutable append-only logs, 90-day retention, encrypted storage
- [ ] **Dashboard**: HTTPS enforced, CSRF tokens, XSS prevention, authentication required
- [ ] **Access Control**: RBAC enforced, all privilege changes logged
- [ ] **Incident Response**: Playbook reviewed by SOC team, versioned in git, signed releases
- [ ] **Vulnerability Scanning**: Container images scanned (Trivy), dependencies audited (OWASP Dep-Check)
- [ ] **Secrets Management**: No hardcoded credentials, API keys in secrets store
- [ ] **Network Segmentation**: SOC isolated from production networks, egress filtering enabled
- [ ] **Monitoring**: Real-time alerts for anomalies in Cybersicker itself
- [ ] **Disaster Recovery**: Backup/restore procedures tested quarterly
- [ ] **Threat Modeling**: Approved by security team, documented in git

---

## 📞 Security Incident Response

**If a security issue is discovered:**

1. **Report**: Email security team with `[CYBERSICKER SECURITY]` subject
2. **Isolate**: Disable affected component (e.g., disable VirusTotal tool if API compromised)
3. **Investigate**: Use Cybersicker's own investigation tools + `/investigate` gstack skill
4. **Remediate**: Follow threat-specific playbook from `playbook.env.txt`
5. **Communicate**: Run `/document-release` to update security advisories

**See:** [Responsible Disclosure Policy](SECURITY_RESPONSE_SLA.md) (TBD)

---

## 📚 References

- **MITRE ATT&CK**: https://attack.mitre.org/
- **NIST CSF 2.0**: https://csrc.nist.gov/projects/cybersecurity-framework
- **NIST AI RMF 1.0**: https://ai.nist.gov/AI%20RMF
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **NIST 800-61**: https://csrc.nist.gov/publications/detail/sp/800-61/rev-3/final (Incident Response)
- **Anthropic Cybersecurity Skills**: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
- **gstack Security Reviews**: https://github.com/garrytan/gstack/docs/security-audit.md

---

**Last Updated:** April 24, 2026  
**Next Review:** Quarterly security audit (use `/cso` gstack skill)
