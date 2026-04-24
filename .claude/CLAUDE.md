# Cybersicker Development Directives for Claude Code

> **Agentic AI IoT Cyberattack Detection System**  
> Version: 2.0 | Last Updated: April 24, 2026

---

## Core Workflow: gstack Sprint Methodology

Use **gstack skills** to structure every feature development cycle following: Think → Plan → Build → Review → Test → Ship → Reflect.

### When to Use Each Skill

| Scenario | Skill | Examples |
|----------|-------|----------|
| **Starting a new threat detection rule** | `/office-hours` | "Build botnet signature detection", "Add ransomware behavioral analysis" |
| **Reviewing detection architecture** | `/plan-eng-review` | "Design new autoencoder feature engineering", "Refactor agent tool orchestration" |
| **SOC dashboard enhancements** | `/plan-design-review` | "Threat heat map visualization", "Incident timeline view" |
| **Before shipping any detection model** | `/cso` | Run OWASP + STRIDE audit on agent tools & model inputs |
| **Testing detection accuracy** | `/qa` | Validate against NSL-KDD dataset, test API integrations |
| **Production deployment** | `/ship` then `/land-and-deploy` | Release new detection rules, playbook updates |
| **Weekly team sync** | `/retro` | Detection false positive rate, agent reasoning quality |

---

## Security-First Development

### Required: Security Review Before Ship
All pull requests touching threat detection must:
1. Pass `/cso` security audit (OWASP Top 10 + STRIDE)
2. Include skill citations from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) in docstrings
3. Document MITRE ATT&CK technique coverage in commit message

**Example:**
```python
@tool
def detect_botnet_traffic(network_logs: str) -> str:
    """
    Detect botnet command-and-control (C2) communication patterns.
    
    Skills Referenced:
    - detecting-botnet-traffic-patterns (threat-hunting)
    - network-traffic-analysis-fundamentals (network-security)
    
    MITRE ATT&CK Coverage:
    - T1571: Non-Standard Port/Protocol
    - T1008: Fallback Channels
    
    Threat Model (STRIDE):
    - Spoofing: Verify packet source via MAC lookup tool
    - Tampering: Validate model predictions with entropy thresholds
    - Repudiation: All alerts logged with timestamps
    """
    ...
```

---

## gstack Skills Available

### Workflow Skills
- `/office-hours` — Reframe threat detection requirements, challenge assumptions
- `/plan-ceo-review` — Strategic scope decisions for SOC expansion
- `/plan-eng-review` — Architecture design for agent + ML components
- `/plan-design-review` — Dashboard UX & SOC interface improvements
- `/plan-devex-review` — Developer experience for security skill library integration
- `/autoplan` — Full review pipeline (CEO → design → eng → DX) with auto-detection

### Implementation & Review
- `/review` — Code quality audit, find production bugs
- `/cso` — Chief Security Officer: OWASP Top 10 + STRIDE threat modeling
- `/codex` — Second opinion: independent review via OpenAI Codex
- `/investigate` — Root-cause debugging for detection accuracy issues

### Testing & Validation
- `/qa` — Live QA: test detection rules against real threat scenarios
- `/qa-only` — Report-only QA without code fixes
- `/benchmark` — Performance baseline: model latency, API response times

### Design & Browser
- `/design-consultation` — Build new SOC dashboard features from scratch
- `/design-shotgun` — Generate 4-6 dashboard mockup variants
- `/design-html` — Turn mockup into production HTML/CSS
- `/design-review` — Designer code review + fixes
- `/browse` or `/open-gstack-browser` — Live web testing, API endpoint validation

### Release & Operations
- `/ship` — Release detection rules, test coverage audit, open PR
- `/land-and-deploy` — Merge, verify CI, deploy to staging/production
- `/canary` — Post-deployment monitoring (console errors, performance)
- `/document-release` — Auto-update README + SECURITY.md + playbooks
- `/retro` — Weekly retrospective: detection accuracy trends, agent quality

### Safety & Utilities
- `/careful` — Warn before destructive commands (rm -rf, DROP TABLE, force-push)
- `/freeze` — Lock edits to one directory during debugging
- `/guard` — Full safety mode (/careful + /freeze)
- `/gstack-upgrade` — Self-update to latest gstack version
- `/learn` — Manage gstack memory across sessions

### AI Security
- `/pair-agent` — Coordinate with another AI agent (OpenClaw, Hermes, Codex)
- `/setup-gbrain` — Persistent knowledge base for cross-session memory

---

## Cybersecurity Skills Integration

### Available Skill Library
- **754 production-grade cybersecurity skills** from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
- **26 security domains** including: Threat Hunting, Malware Analysis, Incident Response, IoT Security, Network Security
- **5-framework coverage**: MITRE ATT&CK, NIST CSF 2.0, MITRE ATLAS, D3FEND, NIST AI RMF

### Skill Domains Required for Cybersicker

| Priority | Domain | Skills | Use Case |
|----------|--------|--------|----------|
| 🔴 Critical | Threat Hunting | 55 | Network anomaly detection, pattern analysis |
| 🔴 Critical | Network Security | 40 | IDS/IPS, firewall rules, traffic analysis |
| 🟠 High | Malware Analysis | 39 | Behavioral detection, file hashing, sandboxing |
| 🟠 High | Incident Response | 25 | Playbook automation, containment procedures |
| 🟡 Medium | IoT/OT Security | 28 | Device fingerprinting, MQTT/CoAP analysis |
| 🟡 Medium | Threat Intelligence | 50 | VirusTotal integration, IP reputation, STIX/TAXII |

### How to Use Skills in Code

**In agent.py tools:**
```python
@tool
def query_threat_intelligence(ip: str) -> str:
    """
    Look up IP reputation via VirusTotal.
    
    Cybersecurity Skill Reference:
    - threat-intelligence-api-integration (Threat Intelligence domain)
    - analyzing-malicious-ip-reputation
    - ip-reputation-scoring-methodology
    
    MITRE ATT&CK: T1592 (Gather Victim Network Information)
    NIST CSF: DE.CM (Security Monitoring)
    """
    ...
```

**In autoencoder.py:**
```python
def extract_network_features(df):
    """
    Extract features for anomaly detection.
    
    Cybersecurity Skill Reference:
    - network-traffic-analysis-fundamentals (Network Security)
    - feature-engineering-for-ml-detection
    - dimensionality-reduction-pca-application
    
    Features selected based on:
    - MITRE ATT&CK techniques: T1566 (Phishing), T1595 (Port Scanning)
    - NIST CSF: DE.CM-01 (Monitor network to detect anomalies)
    """
    ...
```

**In playbook.env.txt:**
```yaml
# Add skill citations to incident response workflows
Ransomware Incident Response:
  Skill Reference: ransomware-incident-response-playbook (Incident Response)
  Step 1 - Containment:
    - Isolate affected IoT devices
    - Skill: network-isolation-segmentation (Network Security)
    - Decision Tree: Use VLAN segmentation or air-gap?
  Step 2 - Investigation:
    - Skill: ransomware-forensics-analysis (Malware Analysis, Incident Response)
    - Timeline reconstruction, file system analysis
```

---

## Project Structure

```
Cybersicker/
├── .claude/
│   ├── CLAUDE.md                    ← This file (workflow directives)
│   ├── gstack/                      ← gstack symlink or submodule
│   └── skills/
│       └── cybersecurity/           ← 754-skill library reference
├── app.py                           ← Streamlit SOC Dashboard (542 L)
├── agent.py                         ← LangChain Agent CLI (121 L)
├── autoencoder.py                   ← ML Anomaly Detection (49 L)
├── playbook.env.txt                 ← Incident Response Playbook
├── INTEGRATION_PLAN.md              ← Strategy for dual-repo integration
├── SECURITY.md                      ← Enhanced: Threat model + skill mappings
├── README.md
└── requirements.txt
```

---

## Threat Model & Security Checklist

**Before shipping any detection rule, validate against STRIDE:**

- [ ] **S — Spoofing** (MAC spoofing, IP spoofing)
  - Skill: `mac-spoofing-detection`, `ip-spoofing-detection`
- [ ] **T — Tampering** (ML model poisoning, packet injection)
  - Skill: `adversarial-ml-attack-defense`, `network-packet-validation`
- [ ] **R — Repudiation** (Attacker denies actions)
  - Skill: `network-log-integrity`, `forensic-logging-procedures`
- [ ] **I — Information Disclosure** (Sensitive data leakage from reports)
  - Skill: `output-data-classification`, `report-sanitization`
- [ ] **D — Denial of Service** (DoS against SOC system itself)
  - Skill: `ddos-mitigation-strategies`, `resource-exhaustion-defense`
- [ ] **E — Elevation of Privilege** (Agent gains unintended permissions)
  - Skill: `privilege-escalation-detection`, `access-control-enforcement`

---

## Development Speed Tips

### Fast Iteration (Day-to-Day)
```bash
# Code + test a new detection rule
code agent.py
# Then:
/qa https://staging.soc.local       # Test it
/review                              # Code quality check
```

### Feature Sprint (Week-Long)
```bash
/office-hours                         # Scope new threat model
/plan-eng-review                      # Architecture
code app.py agent.py autoencoder.py   # Build
/cso                                  # Security audit
/ship                                 # Release
/document-release                     # Update docs
```

### Team Sync (Weekly)
```bash
/retro                                # Detection accuracy trends
```

---

## API Keys & Secrets

Store in `.env` (git-ignored):
```
GOOGLE_API_KEY=...                   # Gemini 2.5 Flash
VIRUSTOTAL_API_KEY=...               # IP reputation lookups
NIST_NVD_API_KEY=...                 # CVE database queries
```

Load with:
```python
from dotenv import load_dotenv
import os
load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")
```

---

## References

- **Main Integration Strategy:** [INTEGRATION_PLAN.md](INTEGRATION_PLAN.md)
- **gstack Workflows:** https://github.com/garrytan/gstack/
- **754 Cybersecurity Skills:** https://github.com/mukul975/Anthropic-Cybersecurity-Skills
- **MITRE ATT&CK Framework:** https://attack.mitre.org/
- **NIST Cybersecurity Framework 2.0:** https://csrc.nist.gov/projects/cybersecurity-framework

---

**Last Updated:** April 24, 2026  
**Next Sync:** Run `/office-hours` to validate integration before Phase 1 implementation
