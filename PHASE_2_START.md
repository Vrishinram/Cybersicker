# 🚀 Phase 2: Start Here

**Current Status:** Phase 1 Complete ✅  
**Next Phase:** Agent Enhancement (Week 2)  
**Estimated Time:** 2-3 hours to implement

---

## 🎯 Phase 2 Objective

Enhance `agent.py` with cybersecurity skill citations, improved API validation, and MITRE ATT&CK mappings.

---

## 📋 Phase 2 Implementation Steps

### Step 1: Open Project in Claude Code

```bash
cd C:\Users\91638\Cybersicker
# Open in Claude Code (VS Code with Claude extension)
code .
```

### Step 2: Start Sprint with /office-hours

**In Claude Code chat:**
```
Type: /office-hours

Then describe:
"I'm implementing Phase 2 of the Cybersicker + gstack + 754-skill integration.
Phase 1 is complete (gstack installed, skills indexed, threat model documented).

For Phase 2, I want to enhance agent.py with:
1. Skill citations in @tool docstrings
2. MITRE ATT&CK mapping for each tool
3. Improved API response validation
4. Device risk profiling for MAC lookups
5. CVSS score interpretation for CVE lookups

Review INTEGRATION_PLAN.md and SKILLS_INDEX.md, then suggest the approach."
```

Claude Code will reframe the problem and provide implementation strategy.

---

### Step 3: Architecture Review

**In Claude Code chat:**
```
/plan-eng-review

Then describe:
"Based on /office-hours output, review the architecture for:
- agent.py tool orchestration changes
- API validation patterns (VirusTotal, NIST NVD)
- Device risk scoring algorithm
- Error handling & rate limiting
- Logging enhancements for audit trail"
```

This creates a detailed architecture document that feeds into Step 4.

---

### Step 4: Make Code Changes

Now implement the changes. Here's the template for each tool:

#### 4.1 Enhanced detect_botnet_traffic Tool

```python
@tool
def detect_botnet_traffic(network_logs: str) -> str:
    """
    Detect botnet command-and-control (C2) communication patterns.
    
    Cybersecurity Skills:
    - detecting-botnet-traffic-patterns (Threat Hunting)
    - network-traffic-analysis-fundamentals (Network Security)
    - c2-communication-patterns (Malware Analysis)
    
    MITRE ATT&CK Techniques Detected:
    - T1571: Non-Standard Port/Protocol
    - T1008: Fallback Channels
    - T1071: Application Layer Protocol
    
    NIST CSF Alignment:
    - DE.CM-01: Monitor network activities
    - DE.AE-02: Detect anomalies
    
    Returns:
        Formatted threat report with confidence scores
    """
    logger.info(f"Detecting botnet patterns in {len(network_logs)} records")
    
    try:
        # Call autoencoder anomaly detection
        anomalies = detect_network_anomalies(network_logs)
        
        # Validate results
        validated = validate_anomaly_scores(anomalies)
        
        # Format with skill reference
        report = f"""
[BOTNET DETECTION] Skill: detecting-botnet-traffic-patterns
MITRE ATT&CK: {', '.join(['T1571', 'T1008', 'T1071'])}
        
Anomalies Detected: {len(validated)}
Confidence: {validated.get('avg_confidence', 0):.1%}
        
Top Indicators:
{format_indicators(validated[:3])}
        """
        logger.info(f"Botnet detection complete: {len(validated)} anomalies")
        return report
        
    except Exception as e:
        logger.error(f"Botnet detection failed: {e}", exc_info=True)
        return f"[Error] Could not analyze network logs: {str(e)}"
```

#### 4.2 Enhanced query_threat_intelligence Tool

```python
@tool
def query_threat_intelligence(ip: str) -> str:
    """
    Check IP reputation via VirusTotal + multi-source intelligence.
    
    Cybersecurity Skills:
    - threat-intelligence-api-integration (Threat Intelligence)
    - analyzing-malicious-ip-reputation
    - geolocation-ip-tracking
    - ip-reputation-scoring-methodology
    
    MITRE ATT&CK:
    - T1592: Gather Victim Network Information
    - T1598: Phishing for Information
    - T1598: Reconnaissance
    
    NIST CSF Alignment:
    - DE.CM-01: Continuous monitoring
    - DE.DP-01: Detection based on threat patterns
    
    Args:
        ip: IPv4 or IPv6 address to analyze
    
    Returns:
        Structured threat intelligence report with risk score
    """
    logger.info(f"Querying threat intelligence for {ip}")
    
    try:
        # Validate IP format
        if not validate_ip_format(ip):
            return f"[Error] Invalid IP format: {ip}"
        
        # Query VirusTotal with response validation
        vt_response = query_virustotal_safe(ip)
        if not vt_response:
            return f"[Warning] VirusTotal API unavailable"
        
        # Query NIST NVD for related CVEs
        related_cves = query_nist_nvd_by_ip(ip)
        
        # Compute reputation score (0-100)
        reputation_score = calculate_reputation_score(vt_response, related_cves)
        
        # Determine threat level
        threat_level = "🔴 CRITICAL" if reputation_score >= 80 else \
                       "🟠 HIGH" if reputation_score >= 60 else \
                       "🟡 MEDIUM" if reputation_score >= 40 else \
                       "🟢 LOW"
        
        # Format report with skill reference
        report = f"""
[THREAT INTELLIGENCE] Skill: threat-intelligence-api-integration
MITRE ATT&CK: T1592 (Gather Victim Network Information)

IP: {ip}
Threat Level: {threat_level}
Reputation Score: {reputation_score}/100

Vendor Detections: {vt_response.get('vendor_count', 0)}
Related CVEs: {len(related_cves)}

Top Threat Types: {', '.join(vt_response.get('threat_types', [])[:3])}
ASN: {vt_response.get('asn', 'Unknown')}
Country: {vt_response.get('country', 'Unknown')}

[RECOMMENDATION]
{"⚠️ BLOCK THIS IP: Malicious activity detected" if reputation_score >= 80 else 
 "🔍 INVESTIGATE: Suspicious indicators present" if reputation_score >= 40 else 
 "✅ ALLOW: Low risk value"}
        """
        logger.info(f"Threat intelligence gathered: {ip} score={reputation_score}")
        return report
        
    except Exception as e:
        logger.error(f"Threat intelligence query failed: {e}", exc_info=True)
        return f"[Error] Could not query threat intelligence: {str(e)}"
```

#### 4.3 Enhanced lookup_mac_address Tool

```python
@tool
def lookup_mac_address(mac: str) -> str:
    """
    Identify IoT device by MAC address + risk profiling.
    
    Cybersecurity Skills:
    - device-fingerprinting-passive (IoT Security)
    - iot-device-discovery-scanning (IoT/OT Security)
    - manufacturer-vulnerability-database
    - shadow-it-discovery
    
    MITRE ATT&CK:
    - T1592: Gather victim network information
    - T1087: Account discovery (device inventory)
    
    NIST CSF Alignment:
    - ID.AM-02: Inventory connected devices
    - PR.AC-01: Access control enforcement
    
    Args:
        mac: MAC address to identify
    
    Returns:
        Device details with manufacturer risk profile
    """
    logger.info(f"Looking up MAC address: {mac}")
    
    try:
        # Validate MAC format
        if not validate_mac_format(mac):
            return f"[Error] Invalid MAC format: {mac}"
        
        # Extract vendor prefix
        vendor_prefix = mac[:8]
        
        # Query MAC vendor database
        vendor_info = query_mac_vendor_database(vendor_prefix)
        if not vendor_info:
            return f"[Unknown] MAC vendor not in database: {mac}"
        
        # Query CVE database for this manufacturer/product
        product_name = vendor_info.get('product', 'Unknown')
        cves = query_manufacturer_vulnerability_database(vendor_info['manufacturer'])
        
        # Determine device risk score
        risk_score = calculate_device_risk_score(vendor_info, cves)
        
        # Format report with skill reference
        report = f"""
[DEVICE IDENTIFICATION] Skill: device-fingerprinting-passive
MITRE ATT&CK: T1592 (Gather Victim Network Information)

MAC Address: {mac}
Manufacturer: {vendor_info.get('manufacturer', 'Unknown')}
Product: {product_name}

Device Risk Score: {risk_score}/100
Known CVEs: {len(cves)}
EOL Status: {vendor_info.get('eol_date', 'Unknown')}

Security Recommendations:
{"⚠️ CRITICAL: Unsupported device - Consider replacement" if vendor_info.get('eol_status') == 'EXPIRED' else 
 "🔴 HIGH: Multiple critical CVEs - Prioritize patching" if len(cves) > 5 else 
 "🟡 MEDIUM: Update available" if vendor_info.get('latest_version') else 
 "🟢 OK: Supported and current"}

Suggested Actions:
- Network segment this device
- Apply latest firmware: {vendor_info.get('latest_version', 'N/A')}
- Monitor for exploitation attempts
        """
        logger.info(f"Device identified: {vendor_info['manufacturer']} {product_name}")
        return report
        
    except Exception as e:
        logger.error(f"MAC lookup failed: {e}", exc_info=True)
        return f"[Error] Could not identify device: {str(e)}"
```

#### 4.4 Enhanced query_nist_cve Tool

```python
@tool
def query_nist_cve(search_term: str) -> str:
    """
    Query NIST NVD for CVE information with CVSS interpretation.
    
    Cybersecurity Skills:
    - cvss-score-interpretation (Vulnerability Management)
    - cve-database-query-techniques (Vulnerability Management)
    - vulnerability-prioritization-matrices
    - exploit-availability-assessment
    - vendor-patch-tracking
    
    MITRE ATT&CK:
    - T1518: Software discovery
    - T1530: Data from infrastructure
    
    NIST CSF Alignment:
    - ID.RA-01: Asset vulnerability identification
    - DE.CM-08: Vulnerability scans
    
    Args:
        search_term: CVE ID or keyword to search
    
    Returns:
        Vulnerability details with remediation guidance
    """
    logger.info(f"Searching NIST NVD for: {search_term}")
    
    try:
        # Query NIST NVD
        results = query_nist_nvd_api(search_term)
        if not results:
            return f"[Info] No CVEs found for: {search_term}"
        
        # Sort by CVSS severity
        sorted_results = sorted(results, 
                               key=lambda x: x.get('cvss_v3_score', 0), 
                               reverse=True)
        
        # Format top 3 results
        report = f"""
[CVE LOOKUP] Skill: cvss-score-interpretation
MITRE ATT&CK: T1518 (Software Discovery)

Search Term: {search_term}
Results Found: {len(results)}

---TOP VULNERABILITIES---
"""
        for i, cve in enumerate(sorted_results[:3], 1):
            cvss_score = cve.get('cvss_v3_score', 0)
            severity = "🔴 CRITICAL" if cvss_score >= 9.0 else \
                      "🟠 HIGH" if cvss_score >= 7.0 else \
                      "🟡 MEDIUM" if cvss_score >= 4.0 else \
                      "🟢 LOW"
            
            report += f"""
{i}. {cve['id']} {severity}
   CVSS Score: {cvss_score}
   Description: {cve['description'][:100]}...
   Published: {cve['published_date']}
   Patch Available: {"✅ Yes" if cve.get('patch_available') else "❌ No"}
"""
        
        logger.info(f"Found {len(results)} CVEs for {search_term}")
        return report
        
    except Exception as e:
        logger.error(f"CVE lookup failed: {e}", exc_info=True)
        return f"[Error] Could not query NIST CVE database: {str(e)}"
```

---

### Step 5: Security Review

**In Claude Code chat:**
```
/cso

This runs OWASP Top 10 + STRIDE threat model audit on your agent.py changes:
- Checks for injection vulnerabilities
- Validates API response handling
- Confirms error handling doesn't leak secrets
- Verifies logging doesn't contain sensitive data
- Confirms prompt injection defenses
```

---

### Step 6: Test with QA

**In Claude Code chat:**
```
/qa https://localhost:8501

(Or your staging URL)

Tests:
- All agent tools execute without errors
- API integrations return valid responses
- No XSS or injection vulnerabilities
- Skill citations appear in output
- Error handling works correctly
```

---

### Step 7: Release with /ship

**In Claude Code chat:**
```
/ship

Automated:
1. Runs all tests
2. Checks code coverage  
3. Runs /cso security audit
4. Opens PR with summary
5. Shows line-of-code metrics
```

---

## ✅ Phase 2 Checklist

- [ ] Step 1: Opened project in Claude Code
- [ ] Step 2: Ran `/office-hours` for strategy
- [ ] Step 3: Ran `/plan-eng-review` for architecture
- [ ] Step 4: Updated agent.py tools (4 tools enhanced)
- [ ] Step 5: Passed `/cso` security audit
- [ ] Step 6: Passed `/qa` automated testing
- [ ] Step 7: Ran `/ship` to create PR
- [ ] Step 8: PR merged to main

---

## 📊 Expected Results After Phase 2

| Metric | Before Phase 2 | After Phase 2 |
|--------|---|---|
| Tool docstrings with skills | 0 | 4/5 tools cited |
| MITRE ATT&CK techniques documented | ~10 | 20+ techniques |
| API response validation | Basic | Strict schema validation |
| Device risk profiling | None | Implemented with CVE correlation |
| CVSS score interpretation | None | Implemented |

---

## 💡 Pro Tips for Phase 2

**Tip 1:** Copy the templates above into your code editor  
**Tip 2:** Use `/cso` output to fix security issues immediately  
**Tip 3:** Run `/qa` before `/ship` to catch bugs early  
**Tip 4:** Add `logger.info()` for audit trail  
**Tip 5:** Always mask PII (IPs, MACs) in output  

---

## 🔗 Reference Files

- `CLAUDE.md` — gstack workflow directives
- `SECURITY.md` — STRIDE threat model
- `SKILLS_INDEX.md` — 754-skill library mapping
- `INTEGRATION_PLAN.md` — Full 4-week roadmap

---

## 🎉 Ready?

When you're ready to start Phase 2:

1. Open Cybersicker in Claude Code
2. Copy this entire Phase_2 Start guide into a Claude Code comment
3. Run `/office-hours` to get started

Or copy the commands verbatim to start immediately:
```
/office-hours
[Describe the Phase 2 goals above]
```

**Estimated Phase 2 Duration:** 2-3 hours  
**Result:** agent.py enhanced with 754-skill integration  
**Next Phase:** Phase 3 — Expand autoencoder.py (Week 3)

---

**Ready to start Phase 2?** →  Open Claude Code and run `/office-hours` 🚀
