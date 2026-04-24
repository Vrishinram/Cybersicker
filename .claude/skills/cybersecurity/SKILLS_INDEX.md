# 🔐 Cybersecurity Skills Reference
## Anthropic Cybersecurity Skills Library Integration

**Repository:** https://github.com/mukul975/Anthropic-Cybersecurity-Skills  
**Total Skills:** 754 across 26 security domains  
**Framework Coverage:** MITRE ATT&CK, NIST CSF 2.0, MITRE ATLAS, D3FEND, NIST AI RMF

---

## 📍 How Skills Map to Cybersicker Components

### 1️⃣ autoencoder.py — Network Anomaly Detection

**Domain: Threat Hunting (55 skills)**
- `detecting-botnet-traffic-patterns` — C2 communication signatures
- `detecting-ddos-volumetric-attacks` — Flood pattern recognition
- `detecting-lateral-movement-in-networks` — Internal reconnaissance indicators
- `detecting-ransomware-traffic-signatures` — Encryption/encoding anomalies
- `detecting-exfiltration-data-transfer-patterns` — Unusual data flows
- `network-traffic-analysis-fundamentals` — Feature engineering baseline

**Domain: Network Security (40 skills)**
- `network-access-control-design` — Segmentation boundaries
- `intrusion-detection-systems-configuration` — IDS/IPS tuning
- `network-packet-analysis-wireshark` — Raw packet inspection
- `traffic-classification-techniques` — Protocol identification

**MITRE ATT&CK Techniques Detected:**
```
T1566 - Phishing (email traffic anomalies)
T1595 - Active Scanning (port scan patterns)
T1498 - Network Denial of Service (volumetric floods)
T1041 - Exfiltration Over C2 (data volume spikes)
T1570 - Lateral Tool Transfer (internal propagation)
T1571 - Non-Standard Port/Protocol (C2 communication)
```

**Use in Code:**
```python
def extract_network_features(df):
    """
    Extract features for ML anomaly detection.
    
    Cybersecurity Skills:
    - network-traffic-analysis-fundamentals
    - feature-engineering-anomaly-ml
    - dimensionality-reduction-pca
    
    MITRE ATT&CK Coverage: T1566, T1595, T1498, T1041
    """
```

---

### 2️⃣ agent.py — LangChain Orchestrator

**Domain: Threat Intelligence (50 skills)**
- `threat-intelligence-api-integration` — API security & rate limiting
- `analyzing-malicious-ip-reputation` — Scoring interpretation
- `whois-ip-registration-lookup` — IP ownership tracking
- `geolocation-ip-tracking` — Geographic threat correlation
- `threat-intel-data-validation` — Response verification

**Domain: Incident Response (25 skills)**
- `ransomware-incident-response-playbook` — Containment procedures
- `ddos-attack-response-procedures` — Mitigation strategies
- `credential-compromise-breach-response` — Investigation workflows
- `incident-response-communication-escalation` — Team alerts
- `evidence-preservation-digital-forensics` — Audit trails

**MITRE ATT&CK Techniques Investigated:**
```
T1592 - Gather Victim Network Information
T1590 - Gather Victim Network Information
T1598 - Phishing for Information
T1589 - Gather Victim Identity Information
T1590 - Gather Victim Network Information
```

**Use in Code:**
```python
@tool
def query_threat_intelligence(ip: str) -> str:
    """
    Check IP reputation via VirusTotal & NIST NVD.
    
    Cybersecurity Skills:
    - threat-intelligence-api-integration
    - analyzing-malicious-ip-reputation
    - ip-reputation-scoring-methodology
    
    MITRE ATT&CK: T1592 (Gather Victim Network Information)
    NIST CSF: DE.CM-01 (Continuous monitoring)
    """
```

---

### 3️⃣ playbook.env.txt — Incident Response Automation

**Domain: Incident Response (25 skills)**
- `ransomware-incident-response-playbook` — 5 phases (detect → contain → investigate → recover → review)
- `ddos-attack-response-procedures` — Real-time mitigation
- `malware-incident-response` — Forensic collection
- `breach-response-procedures` — Exfiltration containment
- `incident-response-communication-tree` — Escalation paths

**Domain: Digital Forensics (37 skills)**
- `evidence-preservation-procedures` — Chain of custody
- `disk-imaging-techniques` — Data capture
- `timeline-reconstruction-forensics` — Attack sequence
- `log-analysis-forensic-investigation` — Evidence correlation

**NIST CSF 2.0 Functions Covered:**
```
RS.RP - Response Planning (Playbook structure)
RS.CO - Communications (Escalation tree)
RS.AN - Analysis (Investigation procedures)
RC.RP - Recovery Planning (Remediation steps)
RC.IM - Improvements (Lessons learned)
```

**Use in Code:**
```yaml
# In playbook.env.txt:
Ransomware Response:
  Skill Reference: ransomware-incident-response-playbook
  Phase 1 - Detection:
    - Detect: Anomaly score > threshold + ransom note
    - Skill: detecting-ransomware-traffic-signatures
  Phase 2 - Containment:
    - Isolate affected IoT devices
    - Skill: network-isolation-segmentation
    - Decision: VLAN vs air-gap?
  Phase 3 - Investigation:
    - Skill: ransomware-forensics-analysis
    - Collect: File hashes, encryption timestamps
  Phase 4 - Recovery:
    - Verify backups
    - Restore from clean snapshot
  Phase 5 - Post-Incident:
    - Skill: incident-response-lessons-learned
    - Review: What detection signals were missed?
```

---

### 4️⃣ app.py — Streamlit Dashboard

**Domain: Web Application Security (42 skills)**
- `xss-prevention-owasp-top-10` — Output encoding, CSP headers
- `api-security-owasp-api-top-10` — Input validation, rate limiting
- `session-management-authentication` — Token handling, CSRF protection
- `access-control-authorization` — RBAC implementation
- `data-exposure-prevention` — PII masking, encryption

**Domain: Compliance & Governance (5 skills)**
- `data-classification-identification` — Sensitivity labeling
- `pii-detection-masking` — Redaction procedures
- `audit-logging-requirements` — Immutable logs
- `access-control-enforcement` — Role-based permissions

**OWASP Top 10 Mappings:**
```
A01:2021 - Broken Access Control → RBAC + Dashboard authorization
A02:2021 - Cryptographic Failures → TLS 1.3, encrypted logs
A03:2021 - Injection → Parameterized queries, input validation
A04:2021 - Insecure Design → STRIDE threat modeling
A05:2021 - Security Misconfiguration → Security headers
A06:2021 - Vulnerable Components → Dependency scanning
A07:2021 - Identification & Auth Failures → Session management
A08:2021 - Software & Data Integrity → Model versioning
A09:2021 - Logging & Monitoring → Immutable audit logs
A10:2021 - SSRF → External API validation
```

---

### 5️⃣ General Security (All Components)

**Domain: AI Risk Management (NIST AI RMF)**
- `prompt-injection-defense-ai` — LLM input sanitization
- `llm-security-vulnerabilities` — Model hardening
- `adversarial-ml-attack-defense` — Evasion resistance
- `data-poisoning-attack-defense` — Training data integrity

**Use in Code:**
```python
# In all components:
@tool
def any_function():
    """
    Function description.
    
    Security Considerations (STRIDE):
    - Spoofing: Validate input source
    - Tampering: Cryptographic validation
    - Repudiation: Audit logging
    - Information Disclosure: Mask PII
    - Denial of Service: Rate limits
    - Elevation of Privilege: RBAC enforcement
    """
```

---

## 🔗 How to Use This Reference

### Step 1: Find Relevant Skill by Component
"I'm working on autoencoder.py" → See "1️⃣ autoencoder.py" section above

### Step 2: Pick Skill from the List
E.g., `detecting-botnet-traffic-patterns` from Threat Hunting domain

### Step 3: Add to Code Docstring
```python
"""
Cybersecurity Skills:
- detecting-botnet-traffic-patterns (Threat Hunting)
- network-traffic-analysis-fundamentals (Network Security)

MITRE ATT&CK: T1571, T1008
"""
```

### Step 4: Reference Full Skill Documentation
Full skill files at: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/

Example: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/detecting-botnet-traffic-patterns/

---

## 📊 Quick Reference: Skills by Domain

| Domain | Count | Key for Cybersicker |
|--------|-------|-------------------|
| 🎯 Threat Hunting | 55 | Network anomaly detection |
| 🌐 Network Security | 40 | Traffic analysis, segmentation |
| 🦠 Malware Analysis | 39 | Behavioral detection, forensics |
| 📋 Incident Response | 25 | Playbook automation, containment |
| ☁️ Cloud Security | 60 | (If Cybersicker deployed to cloud) |
| 🏗️ IoT/OT Security | 28 | Device fingerprinting, protocol analysis |
| 💬 Threat Intelligence | 50 | API integration, IP reputation |
| 🔍 Digital Forensics | 37 | Evidence collection, timeline analysis |
| 🛡️ Web App Security | 42 | Dashboard security, API protection |
| 🔐 Identity & Access Mgmt | 35 | RBAC, authentication (dashboard) |
| 🚨 SOC Operations | 33 | Alert triage, playbook execution |
| 🎯 Red Teaming | 24 | (Validation/testing) |
| 🔬 Penetration Testing | 23 | (Validation/testing) |

---

## ✅ Phase 1 Verification Checklist

- [ ] This file (`SKILLS_INDEX.md`) exists in `.claude/skills/cybersecurity/`
- [ ] gstack cloned to `.claude/skills/gstack/`
- [ ] `CLAUDE.md` shows gstack workflow rules
- [ ] `SECURITY.md` shows STRIDE threat model + mappings
- [ ] `INTEGRATION_PLAN.md` reviewed by team

---

## 🚀 Next Steps

1. **Phase 1 Ready** ✅ (You are here)
2. **Phase 2** → Add skill citations to agent.py tools
3. **Phase 3** → Expand autoencoder.py with skill references & cross-validation
4. **Phase 4** → Update dashboard, deploy with `/ship` gstack skill

---

**Questions?** See:
- `INTEGRATION_PLAN.md` — Full roadmap
- `.claude/CLAUDE.md` — gstack workflow directives
- `SECURITY.md` — Threat model per component
- Full skill library: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
