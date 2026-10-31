"""
CYBERSICKER — NIST NVD REST API 2.0 Client
Asynchronous HTTP client using httpx.AsyncClient for querying CVE advisories,
extracting CVSS v3.1 / v3.0 metrics, severity vectors, exploitability scores,
CWE categorizations, and vendor remediation references.
"""

from __future__ import annotations

import os
import time
import logging
from typing import Dict, Any, Optional, List
import httpx

from app.services.telemetry import telemetry_service

logger = logging.getLogger("Cybersicker.NVD")

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMEOUT = 14.0

# Curated reference database for zero-downtime resilience during NVD rate limits (403/429)
CURATED_CVE_CATALOG: Dict[str, Dict[str, Any]] = {
    "CVE-2024-3094": {
        "published": "2024-03-29",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "exploitability_score": 3.9,
        "impact_score": 6.0,
        "description": "Malicious code discovered in upstream tarballs of xz-utils (liblzma versions 5.6.0 and 5.6.1) that modifies functions in liblzma to intercept OpenSSH sshd process authentication, allowing unauthorized remote actors to bypass authentication and achieve remote code execution.",
        "cwes": ["CWE-506 (Embedded Malicious Code)"],
        "references": [
            "https://access.redhat.com/security/cve/CVE-2024-3094",
            "https://www.openwall.com/lists/oss-security/2024/03/29/4",
            "https://github.com/tukaani-project/xz/security/advisories/GHSA-793r-r98c-8422"
        ],
        "recommendation": "Immediately downgrade xz-utils to 5.4.6 or earlier; inspect all active sshd processes, and revoke compromised SSH host keys."
    },
    "CVE-2021-44228": {
        "published": "2021-12-10",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "exploitability_score": 3.9,
        "impact_score": 6.0,
        "description": "Apache Log4j2 versions 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI-related endpoints, enabling full remote code execution via log message injection.",
        "cwes": ["CWE-502 (Deserialization of Untrusted Data)", "CWE-400 (Uncontrolled Resource Consumption)"],
        "references": [
            "https://logging.apache.org/log4j/2.x/security.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
        ],
        "recommendation": "Upgrade to Apache Log4j 2.17.1 or higher. Alternatively, set environment variable LOG4J_FORMAT_MSG_NO_LOOKUPS=true."
    },
    "CVE-2017-0144": {
        "published": "2017-03-14",
        "cvss_score": 8.1,
        "severity": "HIGH",
        "vector_string": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "exploitability_score": 2.2,
        "impact_score": 5.9,
        "description": "The SMBv1 server in Microsoft Windows Vista SP2, 7 SP1, 8.1, RT 8.1, Server 2008, 2012, and 2016 allows remote attackers to execute arbitrary code via crafted packets (EternalBlue / WannaCry).",
        "cwes": ["CWE-20 (Improper Input Validation)"],
        "references": [
            "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"
        ],
        "recommendation": "Apply Microsoft Security Bulletin MS17-010 and disable SMBv1 globally across the network perimeter."
    },
    "CVE-2023-23397": {
        "published": "2023-03-14",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "exploitability_score": 3.9,
        "impact_score": 5.9,
        "description": "Microsoft Outlook Elevation of Privilege Vulnerability allowing an external attacker to trigger an unauthorized NTLM negotiation by sending a crafted email with a custom reminder sound path.",
        "cwes": ["CWE-290 (Authentication Bypass by Spoofing)"],
        "references": [
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397"
        ],
        "recommendation": "Block egress TCP port 445 (SMB) at the corporate firewall boundary and apply Microsoft Office patch updates."
    }
}


class NVDClient:
    """Asynchronous client for NIST NVD REST API 2.0 vulnerability queries."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("NVD_API_KEY", "").strip()

    async def lookup_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Query NIST NVD 2.0 API for a given CVE ID.
        Extracts CVSS metrics, severity, exploitability score, description, CWEs,
        and vendor references while emitting live telemetry with latency metrics.
        """
        clean_cve = cve_id.strip().upper()
        start_time = time.time()
        url = f"{NVD_BASE_URL}?cveId={clean_cve}"

        headers = {
            "Accept": "application/json",
            "User-Agent": "Cybersicker-SOC-Triage/2.0",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
                response = await client.get(url, headers=headers)
                latency_ms = int((time.time() - start_time) * 1000)

                # Emit telemetry event
                telemetry_service.emit({
                    "event": "LIVE_API_POLL",
                    "service": "NIST_NVD",
                    "target": clean_cve,
                    "latency_ms": latency_ms,
                })

                if response.status_code == 200:
                    data = response.json()
                    vulns = data.get("vulnerabilities", [])

                    if not vulns:
                        return {
                            "event": "NVD_LOOKUP_EMPTY",
                            "cve_id": clean_cve,
                            "found": False,
                            "live_api": True,
                            "note": f"CVE identifier {clean_cve} is not indexed in the NIST NVD database.",
                            "latency_ms": latency_ms,
                        }

                    cve_obj = vulns[0].get("cve", {})
                    published = cve_obj.get("published", "Unknown")[:10]

                    # Description extraction
                    descriptions = cve_obj.get("descriptions", [])
                    desc_text = next(
                        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                        "No English description available."
                    )

                    # Extract CVSS metrics (check 3.1, 3.0, 2.0 in order)
                    metrics = cve_obj.get("metrics", {})
                    cvss_score = 0.0
                    severity = "UNKNOWN"
                    vector_string = "N/A"
                    exploitability_score = 0.0
                    impact_score = 0.0

                    for metric_key in ["cvssMetricV31", "cvssMetricV30"]:
                        if metric_key in metrics and metrics[metric_key]:
                            primary_metric = metrics[metric_key][0]
                            cvss_data = primary_metric.get("cvssData", {})
                            cvss_score = float(cvss_data.get("baseScore", 0.0))
                            severity = cvss_data.get("baseSeverity", "HIGH")
                            vector_string = cvss_data.get("vectorString", "N/A")
                            exploitability_score = float(primary_metric.get("exploitabilityScore", 0.0))
                            impact_score = float(primary_metric.get("impactScore", 0.0))
                            break

                    # CWE extraction
                    cwes: List[str] = []
                    for w in cve_obj.get("weaknesses", []):
                        for desc in w.get("description", []):
                            val = desc.get("value", "")
                            if val and val != "NVD-CWE-Other":
                                cwes.append(val)

                    # References extraction
                    references = [
                        ref.get("url", "") for ref in cve_obj.get("references", [])[:5] if ref.get("url")
                    ]

                    # Remediation recommendation synthesis
                    if cvss_score >= 9.0:
                        recommendation = f"CRITICAL CVSS {cvss_score}: Apply emergency vendor hotfix immediately, restrict network ingress/egress, and isolate vulnerable hosts."
                    elif cvss_score >= 7.0:
                        recommendation = f"HIGH CVSS {cvss_score}: Prioritize patch application within 48 hours; enable perimeter WAF/firewall inspection."
                    else:
                        recommendation = f"CVSS {cvss_score}: Schedule routine patching during next planned maintenance window."

                    return {
                        "event": "NVD_LOOKUP_SUCCESS",
                        "cve_id": clean_cve,
                        "found": True,
                        "live_api": True,
                        "published": published,
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "vector_string": vector_string,
                        "exploitability_score": exploitability_score,
                        "impact_score": impact_score,
                        "description": desc_text,
                        "cwes": cwes or ["Unclassified CWE"],
                        "references": references,
                        "recommendation": recommendation,
                        "latency_ms": latency_ms,
                    }

                elif response.status_code in (403, 429):
                    logger.warning("NIST NVD API returned rate limit status %s for %s", response.status_code, clean_cve)
                    if clean_cve in CURATED_CVE_CATALOG:
                        return {
                            "event": "NVD_RATE_LIMITED_CACHE",
                            "cve_id": clean_cve,
                            "found": True,
                            "live_api": False,
                            "rate_limited": True,
                            **CURATED_CVE_CATALOG[clean_cve],
                            "latency_ms": latency_ms,
                        }

        except httpx.TimeoutException:
            logger.warning("NIST NVD API timed out after %ss for %s", DEFAULT_TIMEOUT, clean_cve)
        except Exception as e:
            logger.error("NIST NVD lookup encountered error: %s", e)

        # Fallback to curated catalog
        latency_ms = int((time.time() - start_time) * 1000)
        telemetry_service.emit({
            "event": "LIVE_API_POLL",
            "service": "NIST_NVD",
            "target": clean_cve,
            "latency_ms": latency_ms,
        })

        if clean_cve in CURATED_CVE_CATALOG:
            return {
                "event": "NVD_CURATED_BASELINE",
                "cve_id": clean_cve,
                "found": True,
                "live_api": False,
                **CURATED_CVE_CATALOG[clean_cve],
                "latency_ms": latency_ms,
            }

        return {
            "event": "NVD_LOOKUP_UNAVAILABLE",
            "cve_id": clean_cve,
            "found": False,
            "live_api": False,
            "note": f"Unable to reach NIST NVD API for {clean_cve} and no cached baseline is present.",
            "latency_ms": latency_ms,
        }


# Global singleton instance
nvd_service = NVDClient()

