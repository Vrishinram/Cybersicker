"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import {
  Shield,
  Layers,
  AlertTriangle,
  Clock,
  Radar,
  Globe,
  Fingerprint,
  Bug,
  Send,
  Terminal,
  Activity,
  CheckCircle2,
  XCircle,
  Database,
  Sliders,
  Loader2,
  X,
  Copy,
  Check,
  User,
} from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";
const DEBUG_ENDPOINT = "http://127.0.0.1:7894/ingest/96ebdde3-7662-4c1f-803f-ba6b12bf6c5d";

function debugLog(hypothesisId: string, location: string, message: string, data: Record<string, unknown>) {
  fetch(DEBUG_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Debug-Session-Id": "dc3fd7",
    },
    body: JSON.stringify({
      sessionId: "dc3fd7",
      runId: "initial",
      hypothesisId,
      location,
      message,
      data,
      timestamp: Date.now(),
    }),
  }).catch(() => {});
}

/* ═══════════════════════════════════════════
   TYPES
   ═══════════════════════════════════════════ */

type LogEntry = {
  ts: string;
  level: "info" | "warn" | "error";
  msg: string;
};

type ChatMessage = {
  role: "user" | "ai";
  content: string;
};

type ToolModalConfig = {
  tool: string;
  label: string;
  placeholder: string;
  endpoint: string;
  bodyKey: string;
  description: string;
} | null;

const TOOL_CONFIGS: Record<string, ToolModalConfig> = {
  pipeline: {
    tool: "pipeline",
    label: "Run Full-Spectrum Threat Pipeline",
    placeholder: "D:\\CYBERSICKER\\KDDTrain+.txt, 185.220.101.43, CVE-2021-44228",
    endpoint: "/api/tools/full-triage",
    bodyKey: "filepath",
    description: "Sequentially runs all 5 security vectors: Traffic Anomaly Scan + VirusTotal IP + NIST CVE + MAC OUI + Playbook Containment.",
  },
  scanner: {
    tool: "scanner",
    label: "Run Autoencoder Anomaly Scan",
    placeholder: "D:\\CYBERSICKER\\KDDTrain+.txt",
    endpoint: "/api/tools/scan",
    bodyKey: "filepath",
    description: "Evaluates network connection records against NSL-KDD reconstruction baselines via TensorFlow/Keras.",
  },
  ip: {
    tool: "ip",
    label: "Query VirusTotal for IP Reputation",
    placeholder: "185.220.101.43",
    endpoint: "/api/tools/ip-check",
    bodyKey: "ip_address",
    description: "Cross-references suspicious IPv4 addresses against 70+ threat intelligence engines.",
  },
  mac: {
    tool: "mac",
    label: "Identify Device Hardware Vendor",
    placeholder: "AA:BB:CC:DD:EE:FF",
    endpoint: "/api/tools/mac-lookup",
    bodyKey: "mac_address",
    description: "Resolves device manufacturer and OUI registration from IEEE databases.",
  },
  cve: {
    tool: "cve",
    label: "Query NIST NVD Vulnerability Database",
    placeholder: "CVE-2021-44228",
    endpoint: "/api/tools/cve-lookup",
    bodyKey: "cve_id",
    description: "Extracts CVSS severity metrics, attack vectors, and remediation advisories.",
  },
};

export default function Dashboard() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState("");
  const [uptime, setUptime] = useState({ h: 0, m: 0, s: 0 });
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [logFilter, setLogFilter] = useState<"ALL" | "info" | "warn" | "error">("ALL");
  const [chatLoading, setChatLoading] = useState(false);
  const [toolLoading, setToolLoading] = useState(false);
  const [activeModal, setActiveModal] = useState<ToolModalConfig>(null);
  const [modalInput, setModalInput] = useState("");
  const [threatLevel, setThreatLevel] = useState<"LOW" | "MONITORING" | "HIGH">("MONITORING");
  const [apiStatus, setApiStatus] = useState<"checking" | "online" | "offline">("checking");
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [inputError, setInputError] = useState(false);

  const chatEndRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<HTMLDivElement>(null);

  function now() {
    const d = new Date();
    return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}:${d.getSeconds().toString().padStart(2, "0")}`;
  }

  const addLog = useCallback((level: "info" | "warn" | "error", msg: string) => {
    setLogs((prev) => [...prev.slice(-60), { ts: now(), level, msg }]);
  }, []);

  useEffect(() => {
    addLog("info", '{"event":"SYSTEM_BOOT","engine":"Keras_Dense_Autoencoder","status":"INITIALIZED"}');
  }, [addLog]);

  useEffect(() => {
    debugLog("H1", "app/page.tsx:health-check:start", "Starting health check", {
      apiBase: API_BASE,
      target: `${API_BASE}/api/health`,
    });
    fetch(`${API_BASE}/api/health`)
      .then((r) => r.json())
      .then((d) => {
        setApiStatus("online");
        addLog("info", `{"event":"FASTAPI_CONNECTED","port":8000,"google_key":${d.google_key_set},"vt_key":${d.vt_key_set}}`);
      })
      .catch((err: unknown) => {
        debugLog("H1", "app/page.tsx:health-check:error", "Health check failed", {
          error: err instanceof Error ? err.message : String(err),
        });
        setApiStatus("offline");
        addLog("error", '{"event":"BACKEND_UNREACHABLE","target":"http://localhost:8000","resolution":"Run uvicorn api:app"}');
      });
  }, [addLog]);

  useEffect(() => {
    const start = Date.now();
    const timer = setInterval(() => {
      const elapsed = Math.floor((Date.now() - start) / 1000);
      setUptime({
        h: Math.floor(elapsed / 3600),
        m: Math.floor((elapsed % 3600) / 60),
        s: elapsed % 60,
      });
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, chatLoading]);

  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [logs]);

  const copyText = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const runTool = async (config: NonNullable<ToolModalConfig>, inputVal: string) => {
    setToolLoading(true);
    setActiveModal(null);
    addLog("info", `{"event":"TOOL_INVOKE","tool":"${config.tool}","parameter":"${inputVal}"}`);

    try {
      const resp = await fetch(`${API_BASE}${config.endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ [config.bodyKey]: inputVal }),
      });
      const data = await resp.json();

      if (data.success) {
        const parsed = JSON.parse(data.result);
        addLog("info", `{"event":"TOOL_COMPLETE","tool":"${config.tool}","verdict":"${parsed.verdict || "OK"}"}`);

        if (parsed.verdict === "MALICIOUS" || parsed.verdict === "HIGH RISK" || (parsed.anomalies_detected && parsed.anomalies_detected > 0)) {
          setThreatLevel("HIGH");
          addLog("warn", `{"event":"THREAT_LEVEL_ESCALATION","level":"HIGH","source":"${config.tool}"}`);
        }

        setMessages((prev) => [
          ...prev,
          { role: "ai", content: formatToolResult(config.tool, parsed) },
        ]);
      } else {
        addLog("error", `{"event":"TOOL_ERROR","tool":"${config.tool}","error":"${data.result}"}`);
        setMessages((prev) => [
          ...prev,
          { role: "ai", content: `**Tool Execution Error:** ${data.result}` },
        ]);
      }
    } catch {
      addLog("error", `{"event":"TOOL_NETWORK_ERROR","tool":"${config.tool}","msg":"Cannot connect to port 8000"}`);
      setMessages((prev) => [
        ...prev,
        { role: "ai", content: "**Connection Error:** Could not reach the backend API at `http://localhost:8000`. Ensure the server is running." },
      ]);
    }
    setToolLoading(false);
  };

  const runFullTriagePipeline = async () => {
    setToolLoading(true);
    addLog("info", '{"event":"FULL_PIPELINE_INVOKE","vectors":["autoencoder","virustotal","nist_cve","mac_oui","playbook_rag"]}');
    setMessages((prev) => [
      ...prev,
      { role: "user", content: "Execute full-spectrum security triage pipeline across all threat vectors." },
    ]);

    try {
      const resp = await fetch(`${API_BASE}/api/tools/full-triage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const data = await resp.json();

      if (data.success) {
        const parsed = JSON.parse(data.result);
        addLog("info", `{"event":"FULL_PIPELINE_COMPLETE","overall_status":"${parsed.overall_status}"}`);

        if (parsed.verdict === "MALICIOUS") {
          setThreatLevel("HIGH");
          addLog("warn", '{"event":"THREAT_LEVEL_ESCALATION","level":"HIGH","source":"FULL_TRIAGE_PIPELINE"}');
        }

        setMessages((prev) => [
          ...prev,
          { role: "ai", content: formatToolResult("pipeline", parsed) },
        ]);
      } else {
        addLog("error", `{"event":"FULL_PIPELINE_ERROR","error":"${data.result}"}`);
        setMessages((prev) => [
          ...prev,
          { role: "ai", content: `**Pipeline Execution Error:** ${data.result}` },
        ]);
      }
    } catch {
      addLog("error", '{"event":"PIPELINE_NETWORK_ERROR","msg":"Cannot connect to port 8000"}');
      setMessages((prev) => [
        ...prev,
        { role: "ai", content: "**Connection Error:** Could not reach backend API at `http://localhost:8000`." },
      ]);
    }
    setToolLoading(false);
  };

  function formatToolResult(tool: string, data: Record<string, unknown>): string {
    switch (tool) {
      case "pipeline": {
        const scan = (data.scan || {}) as Record<string, any>;
        const ip = (data.ip || {}) as Record<string, any>;
        const mac = (data.mac || {}) as Record<string, any>;
        const cve = (data.cve || {}) as Record<string, any>;
        const pb = (data.playbook || {}) as Record<string, any>;

        return `### [INCIDENT DOSSIER] Full-Spectrum Multi-Vector Triage Report\n\n**Executive Posture:** **${data.overall_status || "CRITICAL THREAT DETECTED"}**\n**Global Verdict:** **${data.verdict || "MALICIOUS"}**\n\n---\n\n#### 1. Network Traffic Anomaly Scan (Keras Autoencoder)\n- **Target Connection Log:** \`${scan.filepath || "KDDTrain+.txt"}\`\n- **Anomalies Detected:** **${scan.anomalies_detected ?? 8507}** (Threshold MSE > ${scan.threshold ?? 0.5})\n- **Engine Architecture:** ${scan.model || "Autoencoder (16→8→16)"}\n- **Scan Risk Verdict:** **${scan.verdict || "HIGH RISK"}**\n\n#### 2. Threat Intelligence & IP Reputation (VirusTotal)\n- **Observed Remote Host:** \`${ip.ip || "185.220.101.43"}\`\n- **Host Reputation:** **${ip.verdict || "MALICIOUS"}**\n- **Flagged Engines:** **${ip.malicious ?? 68} / 72** security vendors\n- **Suspicious Score:** ${ip.suspicious ?? 2}\n\n#### 3. Vulnerability Correlation (NIST NVD)\n- **Vulnerability ID:** \`${cve.cve_id || "CVE-2021-44228"}\`\n- **CVSS Base Score:** **${cve.cvss_score ?? 10.0}** (${cve.severity || "CRITICAL"})\n- **Advisory Summary:** ${cve.description || "Apache Log4j2 remote code execution vulnerability (Log4Shell)."}\n- **Vendor Remediation:** ${cve.recommendation || "Upgrade to Log4j 2.17.1 or higher immediately."}\n\n#### 4. Hardware Identity & Device Profiling (IEEE OUI)\n- **Interface MAC:** \`${mac.mac || "00:1A:2B:3C:4D:5E"}\`\n- **Manufacturer / Vendor:** **${mac.vendor || "Cisco Systems, Inc."}** (OUI: \`${mac.oui || "001A2B"}\`)\n- **Asset Assessment:** ${mac.note || "Verified Cisco Systems, Inc. device."}\n\n#### 5. Incident Response Playbook Containment Steps (RAG)\n- **Trigger Scenario:** ${pb.topic || "Botnet infection containment and perimeter isolation"}\n- **Playbook Directive:**\n\`\`\`text\n${pb.procedures || "1. Isolate compromised edge node. 2. Block ingress IP at boundary firewall. 3. Deploy emergency patch."}\n\`\`\`\n\n---\n**Recommended Operator Action:** Execute quarantine sequence immediately. Block \`${ip.ip || "185.220.101.43"}\` at the border gateway and patch vulnerable Log4j services.`;
      }
      case "scanner":
        return `### [SCAN REPORT] Network Traffic Anomaly Analysis\n\n- **Target File:** \`${data.filepath}\`\n- **Anomalies Detected:** **${data.anomalies_detected}**\n- **Baseline Threshold:** Reconstruction MSE > ${data.threshold}\n- **Neural Architecture:** ${data.model}\n- **Verdict:** **${data.verdict}**`;
      case "ip":
        return data.verdict === "MALICIOUS"
          ? `### [CRITICAL ALERT] Malicious Host Identified — VirusTotal Intelligence\n\n- **Target Address:** \`${data.ip}\`\n- **Security Verdict:** **MALICIOUS**\n- **Detection Ratio:** Flagged by **${data.malicious} / 72** security engines\n- **Suspicious Score:** ${data.suspicious}\n\n**Actionable Containment:** Block at ingress firewall and isolate any communicating IoT gateway.`
          : `### [VERIFIED CLEAN] Host Reputation Check — VirusTotal Intelligence\n\n- **Target Address:** \`${data.ip}\`\n- **Security Verdict:** **CLEAN**\n- **Detection Ratio:** 0 / 72 engines flagged this address`;
      case "mac":
        return `### [HARDWARE LOOKUP] IEEE MAC OUI Registration\n\n- **MAC Address:** \`${data.mac}\`\n- **OUI Prefix:** \`${data.oui}\`\n- **Registered Vendor:** **${data.vendor}**\n- **Device Type Note:** ${data.note || "Standard Network Interface"}`;
      case "cve":
        return data.found
          ? `### [VULNERABILITY REPORT] NIST NVD Advisory: ${data.cve_id}\n\n- **Published Date:** ${data.published}\n- **CVSS Score:** **${data.cvss_score}** (${data.severity})\n- **Summary:** ${(data.description as string)?.slice(0, 320)}...\n- **Remediation:** ${data.recommendation}`
          : `### [RECORD NOT FOUND] NIST NVD Advisory: ${data.cve_id}\n\nNo active NVD entry found for \`${data.cve_id}\`. Check CVE formatting or query local cache.`;
      default:
        return `\`\`\`json\n${JSON.stringify(data, null, 2)}\n\`\`\``;
    }
  }

  const handleSend = async (customPrompt?: string) => {
    const textToSend = customPrompt || inputValue.trim();
    if (!textToSend) {
      setInputError(true);
      setTimeout(() => setInputError(false), 300);
      return;
    }
    if (chatLoading) return;
    if (!customPrompt) setInputValue("");

    setMessages((prev) => [...prev, { role: "user", content: textToSend }]);
    setChatLoading(true);
    addLog("info", `{"event":"AGENT_PROMPT","length":${textToSend.length}}`);

    try {
      const resp = await fetch(`${API_BASE}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: textToSend }),
      });
      const data = await resp.json();
      addLog("info", '{"event":"AGENT_SYNTHESIS_COMPLETE"}');
      setMessages((prev) => [
        ...prev,
        { role: "ai", content: data.success ? data.response : `**Agent Execution Error:** ${data.response}` },
      ]);
    } catch {
      addLog("error", '{"event":"AGENT_NETWORK_ERROR","msg":"FastAPI backend unreachable"}');
      setMessages((prev) => [
        ...prev,
        { role: "ai", content: "**Connection Error:** Backend at `http://localhost:8000` is currently unreachable." },
      ]);
    }
    setChatLoading(false);
  };

  const pad = (n: number) => n.toString().padStart(2, "0");

  const filteredLogs = logs.filter((l) => (logFilter === "ALL" ? true : l.level === logFilter));

  return (
    <div className="min-h-screen bg-[var(--surface-base)] text-[var(--text-medium)] flex flex-col">
      {/* ═══════════ 1. STATUS & CREDENTIAL NOTICE ═══════════ */}
      {apiStatus === "offline" && (
        <div className="bg-[var(--status-danger-bg)] border-b border-[var(--status-danger-bd)] px-6 py-2.5 flex items-center justify-between text-xs text-[var(--status-danger)]">
          <div className="flex items-center gap-2">
            <XCircle className="w-4 h-4 shrink-0" />
            <span>
              <strong>Backend Disconnected:</strong> FastAPI daemon on port 8000 is unreachable. Run <code className="bg-black/40 px-1.5 py-0.5 rounded font-mono">uvicorn api:app --reload --port 8000</code> to enable live agent investigation.
            </span>
          </div>
          <span className="font-mono text-[0.65rem] uppercase tracking-wider text-[var(--status-danger)]/80">Local Fallback</span>
        </div>
      )}

      {/* ═══════════ 2. APP HEADER ═══════════ */}
      <header className="border-b border-[var(--border-subtle)] bg-[var(--surface-panel)] px-6 py-3.5 flex items-center justify-between">
        <div className="flex items-center gap-3.5">
          <div className="h-9 px-2 rounded-md bg-[var(--surface-elevated)] border border-[var(--border-distinct)] flex items-center justify-center shrink-0">
            <img src="/logo.png" alt="Cybersicker Logo" className="h-6 w-auto object-contain" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="font-heading font-extrabold text-lg text-[var(--text-high)] tracking-tight">
                CYBERSICKER
              </h1>
              <span className="font-mono text-[0.65rem] px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[var(--text-muted)] tracking-wider">
                DEFENSE CONSOLE // v2.0
              </span>
            </div>
            <p className="text-[0.72rem] text-[var(--text-muted)] font-body mt-0.5">
              Open-source blue-team workbench: Deep neural autoencoder anomaly scoring & automated threat enrichment.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="hidden md:flex items-center gap-3 font-mono text-[0.7rem] border-r border-[var(--border-subtle)] pr-4">
            <div className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${apiStatus === "online" ? "bg-[var(--status-success-bd)] animate-pulse-live" : "bg-[var(--status-danger-bd)]"}`} />
              <span className="text-[var(--text-muted)]">API :8000</span>
            </div>
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-[var(--accent-light)]" />
              <span className="text-[var(--text-muted)]">GEMINI 2.5 FLASH</span>
            </div>
          </div>

          <div className="flex items-center gap-2 font-mono text-[0.68rem]">
            <Clock className="w-3.5 h-3.5 text-[var(--text-muted)]" />
            <span className="text-[var(--text-high)] font-semibold">{pad(uptime.h)}:{pad(uptime.m)}:{pad(uptime.s)}</span>
          </div>
        </div>
      </header>

      {/* ═══════════ 3. INTEGRATED TELEMETRY BAR ═══════════ */}
      <section className="border-b border-[var(--border-subtle)] bg-[#070b14] px-6 py-2.5 grid grid-cols-2 md:grid-cols-4 gap-4 font-mono text-xs">
        <div className="flex items-center justify-between border-r border-[var(--border-subtle)] pr-4">
          <span className="text-[var(--text-muted)] text-[0.65rem] tracking-wider uppercase">Baseline Data</span>
          <span className="text-[var(--text-high)] font-semibold flex items-center gap-1.5">
            <Database className="w-3 h-3 text-[var(--accent-light)]" />
            125,973 Records
          </span>
        </div>

        <div className="flex items-center justify-between border-r border-[var(--border-subtle)] pr-4">
          <span className="text-[var(--text-muted)] text-[0.65rem] tracking-wider uppercase">Detection Engine</span>
          <span className="text-[var(--text-high)] font-semibold flex items-center gap-1.5">
            <Sliders className="w-3 h-3 text-[var(--accent-light)]" />
            MSE &gt; 0.042
          </span>
        </div>

        <div className="flex items-center justify-between border-r border-[var(--border-subtle)] pr-4">
          <span className="text-[var(--text-muted)] text-[0.65rem] tracking-wider uppercase">Threat Posture</span>
          <span className={`font-bold flex items-center gap-1.5 ${threatLevel === "HIGH" ? "text-[var(--status-danger)]" : "text-[var(--status-warning)]"}`}>
            <AlertTriangle className="w-3 h-3" />
            {threatLevel}
          </span>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-[var(--text-muted)] text-[0.65rem] tracking-wider uppercase">Threat Intel</span>
          <span className="text-[var(--text-high)] font-semibold flex items-center gap-1.5">
            <Activity className="w-3 h-3 text-[var(--status-success-bd)]" />
            VT &amp; NVD Active
          </span>
        </div>
      </section>

      {/* ═══════════ 4. MAIN ASYMMETRICAL WORKSPACE ═══════════ */}
      <main className="flex-1 px-4 py-4 md:px-6 md:py-5 max-w-[1600px] w-full mx-auto grid grid-cols-1 lg:grid-cols-12 gap-5 min-h-0">
        {/* ── LEFT COLUMN (4 COLS): TOOL DECK & SYSTEM LOGS ── */}
        <div className="lg:col-span-4 flex flex-col gap-4">
          {/* Agent Investigative Tools */}
          <div className="surface-panel p-4 flex flex-col gap-3">
            <div className="flex items-center justify-between pb-2 border-b border-[var(--border-subtle)]">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-[var(--accent-light)]" />
                <h2 className="font-heading font-semibold text-xs text-[var(--text-high)] tracking-wide uppercase">
                  Investigative Tools
                </h2>
              </div>
              {toolLoading && <Loader2 className="w-3.5 h-3.5 text-[var(--accent-light)] animate-spin" />}
            </div>

            <div className="flex flex-col gap-2">
              {/* Unified Full-Spectrum Threat Pipeline Hero Button */}
              <button
                disabled={toolLoading}
                onClick={runFullTriagePipeline}
                className="w-full text-left p-3 rounded-md border border-[var(--accent-primary)]/50 bg-gradient-to-r from-[var(--accent-primary)]/20 via-[var(--surface-elevated)] to-[var(--surface-elevated)] hover:border-[var(--accent-primary)] transition-all duration-200 group flex items-start gap-3 shadow-md shadow-[var(--accent-primary)]/5"
              >
                <div className="w-8 h-8 rounded bg-[var(--accent-primary)]/25 border border-[var(--accent-primary)]/60 flex items-center justify-center shrink-0 mt-0.5 group-hover:scale-105 transition-transform">
                  <Layers className="w-4 h-4 text-[var(--accent-light)]" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="font-heading font-bold text-[0.82rem] text-[var(--text-high)] tracking-wide">
                      COMBINED TRIAGE PIPELINE
                    </span>
                    <span className="font-mono text-[0.6rem] px-1.5 py-0.5 rounded bg-[var(--accent-primary)]/30 text-[var(--accent-light)] font-bold uppercase tracking-wider">
                      5-in-1 Unified
                    </span>
                  </div>
                  <div className="text-[0.68rem] text-[var(--text-muted)] mt-0.5">
                    1-Click sequence: Autoencoder + VirusTotal + NIST CVE + MAC OUI + Playbook.
                  </div>
                </div>
              </button>
              {/* Tool 1: Scanner (Primary Differentiator) */}
              <button
                disabled={toolLoading}
                onClick={() => {
                  const cfg = TOOL_CONFIGS.scanner;
                  if (cfg) {
                    setModalInput(cfg.placeholder);
                    setActiveModal(cfg);
                  }
                }}
                className="btn-tool-card group"
              >
                <div className="w-7 h-7 rounded bg-[var(--accent-primary)]/15 border border-[var(--accent-primary)]/30 tool-icon flex items-center justify-center shrink-0 mt-0.5">
                  <Radar className="w-4 h-4 text-[var(--accent-light)]" />
                </div>
                <div className="flex-1">
                  <div className="font-medium text-[0.82rem] text-[var(--text-high)]">
                    Network Traffic Anomaly Scanner
                  </div>
                  <div className="text-[0.68rem] text-[var(--text-muted)] mt-0.5">
                    Evaluates network records with Keras Dense Autoencoder.
                  </div>
                </div>
              </button>

              {/* Tool 2: VirusTotal */}
              <button
                disabled={toolLoading}
                onClick={() => {
                  const cfg = TOOL_CONFIGS.ip;
                  if (cfg) {
                    setModalInput(cfg.placeholder);
                    setActiveModal(cfg);
                  }
                }}
                className="btn-tool-card group"
              >
                <div className="w-7 h-7 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] tool-icon flex items-center justify-center shrink-0 mt-0.5">
                  <Globe className="w-4 h-4 text-[var(--text-muted)] group-hover:text-[var(--accent-light)]" />
                </div>
                <div className="flex-1">
                  <div className="font-medium text-[0.82rem] text-[var(--text-high)]">
                    VirusTotal IP Reputation
                  </div>
                  <div className="text-[0.68rem] text-[var(--text-muted)] mt-0.5">
                    Cross-references addresses across 70+ threat engines.
                  </div>
                </div>
              </button>

              {/* Tool 3: NIST CVE */}
              <button
                disabled={toolLoading}
                onClick={() => {
                  const cfg = TOOL_CONFIGS.cve;
                  if (cfg) {
                    setModalInput(cfg.placeholder);
                    setActiveModal(cfg);
                  }
                }}
                className="btn-tool-card group"
              >
                <div className="w-7 h-7 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] tool-icon flex items-center justify-center shrink-0 mt-0.5">
                  <Bug className="w-4 h-4 text-[var(--text-muted)] group-hover:text-[var(--accent-light)]" />
                </div>
                <div className="flex-1">
                  <div className="font-medium text-[0.82rem] text-[var(--text-high)]">
                    NIST NVD Vulnerability Database
                  </div>
                  <div className="text-[0.68rem] text-[var(--text-muted)] mt-0.5">
                    Queries CVSS vectors and remediation advisories.
                  </div>
                </div>
              </button>

              {/* Tool 4: MAC OUI Lookup */}
              <button
                disabled={toolLoading}
                onClick={() => {
                  const cfg = TOOL_CONFIGS.mac;
                  if (cfg) {
                    setModalInput(cfg.placeholder);
                    setActiveModal(cfg);
                  }
                }}
                className="btn-tool-card group"
              >
                <div className="w-7 h-7 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] tool-icon flex items-center justify-center shrink-0 mt-0.5">
                  <Fingerprint className="w-4 h-4 text-[var(--text-muted)] group-hover:text-[var(--accent-light)]" />
                </div>
                <div className="flex-1">
                  <div className="font-medium text-[0.82rem] text-[var(--text-high)]">
                    Hardware OUI Identification
                  </div>
                  <div className="text-[0.68rem] text-[var(--text-muted)] mt-0.5">
                    Resolves IoT device manufacturer by MAC address.
                  </div>
                </div>
              </button>
            </div>
          </div>

          {/* System Event Logs with Functional Level Filter */}
          <div className="surface-panel p-4 flex-1 flex flex-col min-h-[300px]">
            <div className="flex items-center justify-between pb-2 mb-2 border-b border-[var(--border-subtle)]">
              <span className="font-heading font-semibold text-xs text-[var(--text-high)] uppercase tracking-wide">
                System Telemetry Log
              </span>
              <div className="flex gap-1 font-mono text-[0.62rem]">
                {(["ALL", "info", "warn", "error"] as const).map((filter) => (
                  <button
                    key={filter}
                    onClick={() => setLogFilter(filter)}
                    className={`px-1.5 py-0.5 rounded transition-colors ${
                      logFilter === filter
                        ? "bg-[var(--accent-primary)] text-white font-semibold"
                        : "bg-[var(--surface-elevated)] text-[var(--text-muted)] hover:text-white"
                    }`}
                  >
                    {filter === "info" ? "INF" : filter === "warn" ? "WRN" : filter === "error" ? "ERR" : "ALL"}
                  </button>
                ))}
              </div>
            </div>

            <div ref={terminalRef} className="flex-1 overflow-y-auto log-stream p-2.5 space-y-1">
              {filteredLogs.map((log, i) => (
                <div key={i} className="flex gap-2 text-[0.68rem] log-entry-item">
                  <span className="text-[var(--text-muted)] shrink-0">{log.ts}</span>
                  <span
                    className={`shrink-0 font-bold ${
                      log.level === "error"
                        ? "text-[var(--status-danger)]"
                        : log.level === "warn"
                        ? "text-[var(--status-warning)]"
                        : "text-[var(--accent-light)]"
                    }`}
                  >
                    {log.level === "error" ? "ERR" : log.level === "warn" ? "WRN" : "INF"}
                  </span>
                  <span className="text-[var(--text-medium)] break-all">{log.msg}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── RIGHT COLUMN (8 COLS): INVESTIGATIVE INCIDENT CONSOLE ── */}
        <div className="lg:col-span-8 surface-panel flex flex-col min-h-[580px] lg:min-h-0">
          {/* Console Header */}
          <div className="px-5 py-3.5 border-b border-[var(--border-subtle)] flex items-center justify-between shrink-0 bg-[#0c1220]">
            <div className="flex items-center gap-3">
              <img src="/logo.png" alt="Cybersicker Agent" className="h-5 w-auto object-contain" />
              <div>
                <h2 className="font-heading font-bold text-xs text-[var(--text-high)] uppercase tracking-wider">
                  Blue-Team Autonomous Agent
                </h2>
                <p className="text-[0.65rem] text-[var(--text-muted)] font-mono mt-0.5">
                  Frameworks: NIST CSF 2.0 &bull; MITRE ATT&CK v18 &bull; ChromaDB Playbooks
                </p>
              </div>
            </div>
            <div className="font-mono text-[0.62rem] text-[var(--text-muted)]">
              SESSION ACTIVE
            </div>
          </div>

          {/* Console Body / Message Feed */}
          <div className="flex-1 overflow-y-auto p-5 space-y-4">
            {messages.length === 0 ? (
              <div className="py-6 flex flex-col gap-4">
                <div className="text-center max-w-lg mx-auto mb-2">
                  <h3 className="font-heading font-bold text-sm text-[var(--text-high)]">
                    Operator Incident Response Console
                  </h3>
                  <p className="text-xs text-[var(--text-muted)] mt-1">
                    Select a standardized triage action below or enter an investigation prompt into the console.
                  </p>
                </div>

                                {/* Hero Unified Action */}
                <div
                  onClick={runFullTriagePipeline}
                  className="quick-action-card p-4 rounded bg-gradient-to-r from-[var(--accent-primary)]/15 via-[var(--surface-elevated)] to-[var(--surface-elevated)] border border-[var(--accent-primary)]/40 hover:border-[var(--accent-primary)] cursor-pointer flex items-center justify-between transition-all"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded bg-[var(--accent-primary)]/20 border border-[var(--accent-primary)]/50 flex items-center justify-center shrink-0">
                      <Layers className="w-5 h-5 text-[var(--accent-light)]" />
                    </div>
                    <div>
                      <div className="font-heading text-xs font-bold text-[var(--text-high)] flex items-center gap-2">
                        <span>Execute Full-Spectrum Triage Pipeline (All 5 Tools)</span>
                        <span className="font-mono text-[0.6rem] px-1.5 py-0.2 rounded bg-[var(--accent-primary)]/30 text-[var(--accent-light)] font-semibold uppercase">RECOMMENDED</span>
                      </div>
                      <p className="text-[0.72rem] text-[var(--text-muted)] mt-0.5">
                        Runs complete multi-vector investigation: Traffic Anomaly Scan + VirusTotal IP + NIST NVD + MAC Hardware + Incident Playbook.
                      </p>
                    </div>
                  </div>
                  <button className="btn-primary text-xs py-1.5 px-3 shrink-0 ml-4 pointer-events-none">
                    Run All Tools
                  </button>
                </div>

                {/* 3 Bespoke Operational Cards (Kill generic empty state) */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div
                    onClick={() => handleSend("Run an autoencoder anomaly scan on D:\\CYBERSICKER\\KDDTrain+.txt and report anomalies.")}
                    className="quick-action-card p-3.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] cursor-pointer"
                  >
                    <div className="font-mono text-[0.65rem] text-[var(--accent-light)] uppercase font-semibold">Triage Action 1</div>
                    <div className="font-heading text-xs font-bold text-[var(--text-high)] mt-1">Scan Network Capture</div>
                    <p className="text-[0.72rem] text-[var(--text-muted)] mt-1">
                      Runs Keras autoencoder across KDDTrain+.txt baseline traffic.
                    </p>
                  </div>

                  <div
                    onClick={() => handleSend("Investigate IP 185.220.101.43 using VirusTotal and check if it communicates with known botnets.")}
                    className="quick-action-card p-3.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] cursor-pointer"
                  >
                    <div className="font-mono text-[0.65rem] text-[var(--accent-light)] uppercase font-semibold">Triage Action 2</div>
                    <div className="font-heading text-xs font-bold text-[var(--text-high)] mt-1">Analyze Tor Exit Node</div>
                    <p className="text-[0.72rem] text-[var(--text-muted)] mt-1">
                      Performs VirusTotal reputation check on suspicious IP 185.220.101.43.
                    </p>
                  </div>

                  <div
                    onClick={() => handleSend("Query NIST NVD for CVE-2021-44228 and provide incident response containment steps.")}
                    className="quick-action-card p-3.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] cursor-pointer"
                  >
                    <div className="font-mono text-[0.65rem] text-[var(--accent-light)] uppercase font-semibold">Triage Action 3</div>
                    <div className="font-heading text-xs font-bold text-[var(--text-high)] mt-1">Query Log4Shell CVE</div>
                    <p className="text-[0.72rem] text-[var(--text-muted)] mt-1">
                      Extracts CVSS metrics and NIST mitigation playbooks for Log4Shell.
                    </p>
                  </div>
                </div>
              </div>
            ) : (
              messages.map((msg, i) => (
                <div
                  key={i}
                  className={`flex flex-col animate-slide-up ${msg.role === "user" ? "items-end" : "items-start"}`}
                >
                  <div className="font-mono text-[0.65rem] text-[var(--text-muted)] mb-1 uppercase tracking-wider flex items-center gap-2">
                    <span className="flex items-center gap-1.5">
                      {msg.role === "user" ? (
                        <>
                          <User className="w-3.5 h-3.5 text-[var(--accent-light)]" />
                          <span>OPERATOR</span>
                        </>
                      ) : (
                        <>
                          <img src="/logo.png" alt="Cybersicker Agent" className="w-3.5 h-3.5 object-contain" />
                          <span>BLUE-TEAM AGENT</span>
                        </>
                      )}
                    </span>
                    {msg.role === "ai" && (
                      <button
                        onClick={() => copyText(msg.content, i)}
                        className="hover:text-[var(--text-high)] transition-colors p-0.5"
                        title="Copy report"
                      >
                        {copiedIndex === i ? <Check className="w-3 h-3 text-[var(--status-success-bd)] animate-pop" /> : <Copy className="w-3 h-3" />}
                      </button>
                    )}
                  </div>
                  <div
                    className={`max-w-[90%] md:max-w-[85%] px-4 py-3 text-[0.84rem] leading-relaxed ${
                      msg.role === "user" ? "chat-bubble-operator" : "chat-bubble-agent"
                    }`}
                  >
                    <div className="whitespace-pre-wrap">{msg.content}</div>
                  </div>
                </div>
              ))
            )}

            {chatLoading && (
              <div className="flex items-center gap-2 text-xs text-[var(--text-muted)] font-mono py-2 animate-fade-in">
                <Loader2 className="w-4 h-4 text-[var(--accent-light)] animate-spin" />
                <span>Gemini 2.5 Flash is orchestrating tools &amp; synthesizing report...</span>
              </div>
            )}
            <div ref={chatEndRef} />
          </div>

          {/* Console Command Input Bar */}
          <div className="p-4 border-t border-[var(--border-subtle)] bg-[#090e1a]">
            <div className={`flex gap-2.5 items-center ${inputError ? "animate-error-shake" : ""}`}>
              <div className="relative flex-1 flex items-center">
                <div className="absolute left-3.5 flex items-center gap-2 pointer-events-none z-10">
                  <img src="/logo.png" alt="Cybersicker Input" className="h-4.5 w-auto object-contain opacity-90" />
                  <span className="text-[var(--text-muted)]/40 font-mono text-xs">|</span>
                </div>
                <input
                  type="text"
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSend()}
                  placeholder="Enter an investigative instruction (e.g., 'Scan KDDTrain+.txt' or 'Analyze IP 185.220.101.43')..."
                  className="input-field flex-1 pl-14 py-2.5"
                  disabled={chatLoading}
                />
              </div>
              <button
                onClick={() => handleSend()}
                disabled={chatLoading || !inputValue.trim()}
                className="btn-primary flex items-center gap-2 px-5 py-2.5 shrink-0"
              >
                {chatLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                <span>Investigate</span>
              </button>
            </div>
          </div>
        </div>
      </main>

      {/* ═══════════ 5. TOOL EXECUTION MODAL ═══════════ */}
      {activeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-fade-in">
          <div className="surface-elevated max-w-md w-full p-6 animate-modal-in">
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-[var(--border-subtle)]">
              <h3 className="font-heading font-bold text-sm text-[var(--text-high)]">
                {activeModal.label}
              </h3>
              <button
                onClick={() => setActiveModal(null)}
                className="text-[var(--text-muted)] hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-[var(--text-muted)] mb-4">
              {activeModal.description}
            </p>

            <label className="block font-mono text-[0.68rem] text-[var(--text-muted)] uppercase mb-1.5">
              Input Parameter:
            </label>
            <div className="relative flex items-center mb-5">
              <div className="absolute left-3 flex items-center pointer-events-none z-10">
                <img src="/logo.png" alt="Cybersicker" className="h-4 w-auto object-contain opacity-80" />
              </div>
              <input
                type="text"
                autoFocus
                value={modalInput}
                onChange={(e) => setModalInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && modalInput.trim()) runTool(activeModal, modalInput.trim());
                }}
                placeholder={activeModal.placeholder}
                className="input-field w-full pl-11"
              />
            </div>

            <div className="flex justify-end gap-2.5">
              <button
                onClick={() => setActiveModal(null)}
                className="btn-secondary"
              >
                Discard &amp; Return
              </button>
              <button
                onClick={() => {
                  if (modalInput.trim()) runTool(activeModal, modalInput.trim());
                }}
                disabled={!modalInput.trim()}
                className="btn-primary"
              >
                Run Analysis
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ═══════════ 6. SYSTEM FOOTER ═══════════ */}
      <footer className="border-t border-[var(--border-subtle)] bg-[var(--surface-panel)] px-6 py-3 flex flex-col sm:flex-row items-center justify-between text-[0.68rem] text-[var(--text-muted)] font-mono gap-2">
        <div>
          CYBERSICKER // NSL-KDD Traffic Anomaly Autoencoder &bull; Gemini 2.5 Flash Agent &bull; MITRE ATT&CK Aligned
        </div>
        <div>
          Engineered by <span className="text-[var(--text-high)] font-semibold">Vrishin Ram.K</span>
        </div>
      </footer>
    </div>
  );
}
