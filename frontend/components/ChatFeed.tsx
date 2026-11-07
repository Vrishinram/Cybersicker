"use client";

import React, { useState, useEffect, useRef } from "react";
import {
  User,
  Copy,
  Check,
  ShieldAlert,
  ShieldCheck,
  ExternalLink,
  Download,
  Layers,
  Globe,
  Loader2,
} from "lucide-react";
import { createStix21Bundle, downloadStix21Bundle } from "../app/utils/stix_exporter";

export interface ChatMessage {
  role: "user" | "ai";
  content: string;
}

interface ChatFeedProps {
  messages: ChatMessage[];
  chatLoading: boolean;
  blockedIps: Set<string>;
  onBlockIp: (ip: string) => void;
  onRunFullPipeline: () => void;
  onSendPresetMessage: (prompt: string) => void;
  onLogEvent?: (level: "info" | "warn" | "error", msg: string) => void;
}

export function parseThreatIndicators(text: string) {
  const ipMatches = text.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g);
  const threatIp = ipMatches?.find((ip) => ip !== "127.0.0.1" && ip !== "0.0.0.0") || null;
  const cveMatch = text.match(/CVE-\d{4}-\d{4,7}/i);
  const threatCve = cveMatch ? cveMatch[0].toUpperCase() : null;
  const isDossier =
    text.includes("[INCIDENT") ||
    text.includes("Playbook") ||
    text.includes("SOP-") ||
    text.includes("Full-Spectrum") ||
    text.includes("TRAFFIC CAPTURE") ||
    text.includes("ANOMALY DETECTION");

  // Determine security verdict from response content
  let verdict: "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "UNKNOWN" = "UNKNOWN";
  const upper = text.toUpperCase();

  // Known clean public recursive resolvers or explicitly clean text
  const isExplicitlyClean =
    upper.includes("SECURITY VERDICT:** **CLEAN") ||
    upper.includes("[VERIFIED CLEAN]") ||
    upper.includes("VERDICT: CLEAN") ||
    upper.includes("VERDICT:** **CLEAN") ||
    upper.includes("0 / 72 ENGINES") ||
    upper.includes("0 / 72 SECURITY") ||
    upper.includes("CLEAN PUBLIC DNS") ||
    (threatIp === "8.8.8.8" && !upper.includes("MALICIOUS")) ||
    (threatIp === "1.1.1.1" && !upper.includes("MALICIOUS")) ||
    (threatIp === "9.9.9.9" && !upper.includes("MALICIOUS"));

  if (isExplicitlyClean) {
    verdict = "CLEAN";
  } else if (
    upper.includes("MALICIOUS") ||
    upper.includes("CRITICAL ALERT") ||
    upper.includes("HIGH RISK") ||
    upper.includes("HIGH_RISK")
  ) {
    verdict = "MALICIOUS";
  } else if (upper.includes("SUSPICIOUS") || upper.includes("ANOMALOUS")) {
    verdict = "SUSPICIOUS";
  }

  return { threatIp, threatCve, isDossier, verdict };
}

export default function ChatFeed({
  messages,
  chatLoading,
  blockedIps,
  onBlockIp,
  onRunFullPipeline,
  onSendPresetMessage,
  onLogEvent,
}: ChatFeedProps) {
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const [copiedRuleIp, setCopiedRuleIp] = useState<string | null>(null);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  // Auto-scroll on new messages or loading states
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, chatLoading]);

  // Requirement 1: Copy Containment Rule with "Copied!" green feedback for 2000ms
  const handleCopyContainmentRule = async (ip: string) => {
    const rule = `iptables -A INPUT -s ${ip} -j DROP`;
    try {
      await navigator.clipboard.writeText(rule);
      setCopiedRuleIp(ip);
      onLogEvent?.("info", JSON.stringify({ event: "CONTAINMENT_RULE_COPIED", rule, target_ip: ip }));
      setTimeout(() => {
        setCopiedRuleIp(null);
      }, 2000);
    } catch {
      setCopiedRuleIp(ip);
      setTimeout(() => setCopiedRuleIp(null), 2000);
    }
  };

  const handleCopyText = async (text: string, index: number) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedIndex(index);
      setTimeout(() => setCopiedIndex(null), 1500);
    } catch {
      // Fallback
    }
  };

  // Requirement 1: Neutral action [Inspect ASN / WHOIS] for CLEAN hosts
  const handleInspectAsnWhois = (ip: string) => {
    onLogEvent?.("info", JSON.stringify({ event: "ASN_WHOIS_LOOKUP", target_ip: ip, registry: "BGP.HE.NET / ARIN" }));
    if (typeof window !== "undefined") {
      window.open(`https://bgp.he.net/ip/${ip}`, "_blank", "noopener,noreferrer");
    }
  };

  // Client-Side STIX 2.1 Bundle Export
  const handleExportStixBundle = (content: string, ip?: string | null, cve?: string | null, verdict: string = "MALICIOUS") => {
    onLogEvent?.("info", JSON.stringify({ event: "STIX_EXPORT_REQUESTED", spec_version: "2.1", ip, cve }));
    try {
      const bundle = createStix21Bundle({
        ip,
        cve,
        verdict,
        notes: content,
        title: ip ? `Threat Triage Incident — ${ip}` : "Autonomous Blue-Team Triage",
      });
      downloadStix21Bundle(bundle, "cybersicker_stix21_export.json");
      onLogEvent?.("info", JSON.stringify({ event: "STIX_BUNDLE_EXPORTED", bundle_id: bundle.id, file: "cybersicker_stix21_export.json" }));
    } catch (err) {
      onLogEvent?.("error", JSON.stringify({ event: "STIX_EXPORT_FAILED", error: String(err) }));
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-4 md:p-6 space-y-6">
      {messages.length === 0 ? (
        <div className="h-full flex flex-col justify-center max-w-2xl mx-auto py-8 space-y-6 animate-slide-up">
          <div className="text-center space-y-2">
            <h2 className="font-heading font-extrabold text-xl text-[var(--text-high)] tracking-tight">
              Blue-Team Security Operations Workbench
            </h2>
            <p className="text-xs text-[var(--text-muted)] max-w-md mx-auto leading-relaxed">
              Synthesize neural network flow anomaly detections with live VirusTotal, NIST NVD, and IEEE MAC intelligence.
            </p>
          </div>

          {/* Full Pipeline Action Card */}
          <div
            onClick={onRunFullPipeline}
            className="quick-action-card p-4 rounded-lg bg-gradient-to-r from-[var(--accent-primary)]/20 via-[var(--surface-elevated)] to-[var(--surface-elevated)] border border-[var(--accent-primary)]/50 hover:border-[var(--accent-light)] cursor-pointer flex items-center justify-between shadow-lg group"
          >
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-md bg-[var(--accent-primary)]/25 border border-[var(--accent-primary)]/60 flex items-center justify-center shrink-0 group-hover:scale-105 group-hover:border-[var(--accent-light)] transition-all">
                <Layers className="w-5 h-5 text-[var(--accent-light)]" />
              </div>
              <div>
                <div className="font-heading text-xs font-bold text-[var(--text-high)] flex items-center gap-2">
                  <span>Execute Full-Spectrum Triage Pipeline (All 5 Tools)</span>
                  <span className="font-mono text-[0.6rem] px-2 py-0.5 rounded bg-[var(--accent-primary)]/30 text-[var(--accent-light)] border border-[var(--accent-primary)]/40 font-semibold uppercase">
                    RECOMMENDED
                  </span>
                </div>
                <p className="text-[0.72rem] text-[var(--text-muted)] mt-0.5">
                  Runs complete multi-vector investigation: Traffic Anomaly Scan + VirusTotal IP + NIST NVD + MAC Hardware + Incident Playbook.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onRunFullPipeline();
              }}
              className="btn-primary text-xs py-2 px-4 shrink-0 ml-4 font-semibold shadow-md active:scale-95 transition-all"
            >
              Run All Tools
            </button>
          </div>

          {/* 3 Bespoke Operational Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div
              onClick={() => onSendPresetMessage("Run an autoencoder anomaly scan on KDDTrain+.txt and report anomalies.")}
              className="quick-action-card p-3.5 rounded-lg bg-[var(--surface-elevated)] border border-[var(--border-distinct)] cursor-pointer group"
            >
              <div className="font-mono text-[0.65rem] text-[var(--accent-light)] uppercase font-semibold flex items-center justify-between">
                <span>Triage Action 1</span>
                <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-light)] opacity-70 group-hover:opacity-100" />
              </div>
              <div className="font-heading text-xs font-bold text-[var(--text-high)] mt-1.5 group-hover:text-white transition-colors">
                Scan Network Capture
              </div>
              <p className="text-[0.72rem] text-[var(--text-muted)] mt-1 leading-snug">
                Runs Keras autoencoder across KDDTrain+.txt baseline traffic.
              </p>
            </div>

            <div
              onClick={() => onSendPresetMessage("Investigate IP 185.220.101.43 using VirusTotal and check if it communicates with known botnets.")}
              className="quick-action-card p-3.5 rounded-lg bg-[var(--surface-elevated)] border border-[var(--border-distinct)] cursor-pointer group"
            >
              <div className="font-mono text-[0.65rem] text-[var(--accent-light)] uppercase font-semibold flex items-center justify-between">
                <span>Triage Action 2</span>
                <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-light)] opacity-70 group-hover:opacity-100" />
              </div>
              <div className="font-heading text-xs font-bold text-[var(--text-high)] mt-1.5 group-hover:text-white transition-colors">
                Analyze Tor Exit Node
              </div>
              <p className="text-[0.72rem] text-[var(--text-muted)] mt-1 leading-snug">
                Performs VirusTotal reputation check on suspicious IP 185.220.101.43.
              </p>
            </div>

            <div
              onClick={() => onSendPresetMessage("Query NIST NVD for CVE-2024-3094 and provide incident response containment steps.")}
              className="quick-action-card p-3.5 rounded-lg bg-[var(--surface-elevated)] border border-[var(--border-distinct)] cursor-pointer group"
            >
              <div className="font-mono text-[0.65rem] text-[var(--accent-light)] uppercase font-semibold flex items-center justify-between">
                <span>Triage Action 3</span>
                <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-light)] opacity-70 group-hover:opacity-100" />
              </div>
              <div className="font-heading text-xs font-bold text-[var(--text-high)] mt-1.5 group-hover:text-white transition-colors">
                Query XZ Utils Backdoor
              </div>
              <p className="text-[0.72rem] text-[var(--text-muted)] mt-1 leading-snug">
                Extracts CVSS 10.0 metrics and NIST mitigation playbooks for CVE-2024-3094.
              </p>
            </div>
          </div>
        </div>
      ) : (
        messages.map((msg, i) => {
          const { threatIp, threatCve, isDossier, verdict } = parseThreatIndicators(msg.content);
          return (
            <div
              key={i}
              className={`flex flex-col animate-slide-up ${msg.role === "user" ? "items-end" : "items-start"}`}
            >
              <div className="font-mono text-[0.65rem] text-[var(--text-muted)] mb-1.5 uppercase tracking-wider flex items-center gap-2">
                <span className="flex items-center gap-1.5">
                  {msg.role === "user" ? (
                    <>
                      <User className="w-3.5 h-3.5 text-[var(--accent-light)]" />
                      <span className="font-semibold text-[var(--text-medium)]">OPERATOR</span>
                    </>
                  ) : (
                    <>
                      <img src="/logo.png" alt="Cybersicker Agent" className="w-3.5 h-3.5 object-contain" />
                      <span className="font-semibold text-[var(--accent-light)]">BLUE-TEAM AGENT</span>
                    </>
                  )}
                </span>
                {msg.role === "ai" && (
                  <button
                    onClick={() => handleCopyText(msg.content, i)}
                    className="hover:text-[var(--text-high)] transition-colors p-0.5 cursor-pointer ml-1"
                    title="Copy report"
                  >
                    {copiedIndex === i ? (
                      <Check className="w-3.5 h-3.5 text-[#00ff9d]" />
                    ) : (
                      <Copy className="w-3 h-3 text-[var(--text-muted)] hover:text-white" />
                    )}
                  </button>
                )}
              </div>

              <div
                className={`max-w-[92%] md:max-w-[85%] px-4 py-3.5 text-[0.84rem] leading-relaxed shadow-md ${
                  msg.role === "user" ? "chat-bubble-operator" : "chat-bubble-agent"
                }`}
              >
                <div className="whitespace-pre-wrap">{msg.content}</div>

                {/* Actionable Response Controls (Active Defense Buttons) */}
                {msg.role === "ai" && (threatIp || threatCve || isDossier) && (
                  <div className="mt-3.5 pt-3 border-t border-[var(--border-subtle)] flex flex-wrap items-center gap-2 text-xs font-mono">
                    {/* Requirement 1: Conditional IP Controls based on verdict */}
                    {threatIp && (
                      <>
                        {/* If MALICIOUS or SUSPICIOUS -> render containment actions */}
                        {verdict === "MALICIOUS" || verdict === "SUSPICIOUS" ? (
                          <>
                            <button
                              onClick={() => handleCopyContainmentRule(threatIp)}
                              className="active-defense-btn px-2.5 py-1.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] text-[var(--text-medium)] hover:text-white hover:border-[var(--accent-light)] flex items-center gap-1.5 text-[0.7rem] cursor-pointer"
                            >
                              {copiedRuleIp === threatIp ? (
                                <>
                                  <Check className="w-3.5 h-3.5 text-[#00ff9d]" />
                                  <span className="text-[#00ff9d] font-semibold">Copied!</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3.5 h-3.5 text-[var(--accent-light)]" />
                                  <span>Copy Containment Rule</span>
                                </>
                              )}
                            </button>

                            <button
                              onClick={() => onBlockIp(threatIp)}
                              disabled={blockedIps.has(threatIp)}
                              className={`active-defense-btn px-2.5 py-1.5 rounded border flex items-center gap-1.5 text-[0.7rem] cursor-pointer ${
                                blockedIps.has(threatIp)
                                  ? "bg-[var(--status-danger-bg)] border-[var(--status-danger-bd)] text-[var(--status-danger)] cursor-not-allowed opacity-90"
                                  : "bg-[var(--status-danger-bg)]/50 border-[var(--status-danger-bd)]/70 text-[var(--status-danger)] hover:bg-[var(--status-danger-bg)] hover:border-[var(--status-danger-bd)]"
                              }`}
                            >
                              {blockedIps.has(threatIp) ? (
                                <>
                                  <ShieldCheck className="w-3.5 h-3.5 text-[#00ff9d]" />
                                  <span className="font-semibold">Blocked at Border</span>
                                </>
                              ) : (
                                <>
                                  <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                                  <span>Block Border Ingress</span>
                                </>
                              )}
                            </button>
                          </>
                        ) : (
                          /* If verdict === 'CLEAN' -> render neutral [Inspect ASN / WHOIS] */
                          <button
                            onClick={() => handleInspectAsnWhois(threatIp)}
                            className="active-defense-btn px-2.5 py-1.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] text-[var(--accent-light)] hover:bg-[var(--accent-primary)]/20 hover:border-[var(--accent-light)] flex items-center gap-1.5 text-[0.7rem] cursor-pointer"
                          >
                            <Globe className="w-3.5 h-3.5 text-[var(--accent-light)]" />
                            <span>Inspect ASN / WHOIS</span>
                          </button>
                        )}
                      </>
                    )}

                    {/* CVE NIST Advisory Link */}
                    {threatCve && (
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${threatCve}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="active-defense-btn px-2.5 py-1.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] text-[var(--text-medium)] hover:text-white hover:border-[var(--accent-light)] flex items-center gap-1.5 text-[0.7rem] cursor-pointer"
                      >
                        <ExternalLink className="w-3.5 h-3.5 text-[var(--accent-light)]" />
                        <span>View NIST Advisory ({threatCve})</span>
                      </a>
                    )}

                    {/* STIX 2.1 Export Button */}
                    {(isDossier || threatIp || threatCve) && (
                      <button
                        onClick={() => handleExportStixBundle(msg.content, threatIp, threatCve, verdict)}
                        className="active-defense-btn px-2.5 py-1.5 rounded bg-[var(--surface-elevated)] border border-[var(--accent-primary)]/50 text-[var(--accent-light)] hover:bg-[var(--accent-primary)]/25 hover:border-[var(--accent-light)] flex items-center gap-1.5 text-[0.7rem] cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Export STIX 2.1 Bundle</span>
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })
      )}

      {/* Elegant Multi-Step Blue-Team Loading State */}
      {chatLoading && (
        <div className="flex flex-col gap-2.5 p-4 rounded-lg bg-[var(--surface-panel)] border border-[var(--border-distinct)] animate-slide-up shadow-xl max-w-lg">
          <div className="flex items-center justify-between text-xs font-mono text-[var(--text-muted)] pb-2 border-b border-[var(--border-subtle)]">
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[var(--accent-light)] animate-ping" />
              <span className="text-[var(--text-high)] font-semibold uppercase tracking-wider">Blue-Team Dispatch Active</span>
            </span>
            <span className="text-[var(--accent-light)] font-mono text-[0.65rem] animate-pulse">INVESTIGATING...</span>
          </div>
          <div className="flex items-center gap-3 py-1">
            <Loader2 className="w-5 h-5 text-[var(--accent-light)] animate-spin shrink-0" />
            <div className="text-[0.78rem] text-[var(--text-medium)] font-body leading-snug">
              Correlating multi-vector telemetry, executing deep autoencoder inference, and synthesizing Blue-Team Incident Report...
            </div>
          </div>
          <div className="w-full bg-[var(--surface-elevated)] h-1.5 rounded-full overflow-hidden mt-1">
            <div className="h-full bg-gradient-to-r from-[var(--accent-primary)] via-[var(--accent-light)] to-[var(--accent-primary)] animate-shimmer w-full" />
          </div>
        </div>
      )}

      <div ref={messagesEndRef} />
    </div>
  );
}
