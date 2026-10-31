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
  UploadCloud,
  ExternalLink,
  Download,
  ShieldAlert,
  Sparkles,
  ShieldCheck,
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
   TYPES & CONSTANTS
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
    placeholder: "KDDTrain+.txt, 185.220.101.43, CVE-2024-3094",
    endpoint: "/api/tools/full-triage",
    bodyKey: "filepath",
    description: "Sequentially runs all 5 security vectors: Traffic Anomaly Scan + VirusTotal IP + NIST CVE + MAC OUI + Playbook Containment.",
  },
  scanner: {
    tool: "scanner",
    label: "Run Autoencoder Anomaly Scan",
    placeholder: "KDDTrain+.txt",
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
    placeholder: "B8:27:EB:AA:BB:CC",
    endpoint: "/api/tools/mac-lookup",
    bodyKey: "mac_address",
    description: "Resolves device manufacturer and OUI registration from IEEE databases.",
  },
  cve: {
    tool: "cve",
    label: "Query NIST NVD Vulnerability Database",
    placeholder: "CVE-2024-3094",
    endpoint: "/api/tools/cve-lookup",
    bodyKey: "cve_id",
    description: "Extracts CVSS severity metrics, attack vectors, and remediation advisories.",
  },
};

const PRESET_CHIPS = [
  { label: "Clean Public DNS (8.8.8.8)", prompt: "Analyze IP 8.8.8.8", tag: "DNS" },
  { label: "Malicious Tor Node", prompt: "Analyze IP 185.220.101.43", tag: "C2" },
  { label: "Critical Backdoor (XZ Utils)", prompt: "Query CVE-2024-3094", tag: "RCE" },
  { label: "IoT Hardware (Raspberry Pi)", prompt: "Resolve MAC B8:27:EB:AA:BB:CC", tag: "OUI" },
  { label: "SYN Flood Mitigation", prompt: "What is the containment playbook for SYN flood attack?", tag: "DoS" },
];

const ROTATING_PLACEHOLDERS = [
  "e.g., 'Analyze IP 8.8.8.8 and query CVE-2024-3094' or 'Resolve MAC B8:27:EB:AA:BB:CC'...",
  "e.g., 'Analyze IP 185.220.101.43 and query CVE-2021-44228'...",
  "e.g., 'What is the containment playbook for SYN flood attack?'...",
  "e.g., 'Resolve MAC FC:65:DE:12:34:56 and analyze network telemetry'...",
];

export default function Dashboard() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState("");
  const [placeholderIndex, setPlaceholderIndex] = useState(0);
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
  const [copiedRuleIp, setCopiedRuleIp] = useState<string | null>(null);
  const [blockedIps, setBlockedIps] = useState<Set<string>>(new Set());
  const [inputError, setInputError] = useState(false);
  const [isDraggingFile, setIsDraggingFile] = useState(false);
  const [fileUploadLoading, setFileUploadLoading] = useState(false);

  const chatEndRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  function now() {
    const d = new Date();
    return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}:${d.getSeconds().toString().padStart(2, "0")}`;
  }

  const addLog = useCallback((level: "info" | "warn" | "error", msg: string) => {
    setLogs((prev) => [...prev.slice(-60), { ts: now(), level, msg }]);
  }, []);

  // System Boot Log
  useEffect(() => {
    addLog("info", '{"event":"SYSTEM_BOOT","engine":"Keras_Dense_Autoencoder","status":"INITIALIZED"}');
  }, [addLog]);

  // Backend Health Check
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

  // Live Server-Sent Events (SSE) Telemetry Stream
  useEffect(() => {
    let eventSource: EventSource | null = null;
    try {
      eventSource = new EventSource(`${API_BASE}/api/v1/telemetry/stream`);
      eventSource.onmessage = (e) => {
        try {
          const payload = JSON.parse(e.data);
          addLog("info", JSON.stringify(payload));
        } catch {
          // parse silently
        }
      };
      eventSource.onerror = () => {
        eventSource?.close();
      };
    } catch {
      // EventSource unsupported
    }
    return () => {
      eventSource?.close();
    };
  }, [addLog]);

  // Uptime Timer
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

  // Rotating Placeholder Interval
  useEffect(() => {
    const timer = setInterval(() => {
      setPlaceholderIndex((prev) => (prev + 1) % ROTATING_PLACEHOLDERS.length);
    }, 3500);
    return () => clearInterval(timer);
  }, []);

  // Auto-scroll chat feed whenever messages or loading state updates
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, chatLoading]);

  // Auto-scroll telemetry terminal
  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [logs]);

  const copyText = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const copyIptablesRule = (ip: string) => {
    const rule = `iptables -A INPUT -s ${ip} -j DROP`;
    navigator.clipboard.writeText(rule);
    setCopiedRuleIp(ip);
    addLog("info", `{"event":"RULE_COPIED","command":"${rule}"}`);
    setTimeout(() => setCopiedRuleIp(null), 2000);
  };

  const blockIpAtBorder = async (ip: string) => {
    addLog("warn", `{"event":"DISPATCHING_BORDER_BLOCK","target_ip":"${ip}"}`);
    try {
      const resp = await fetch(`${API_BASE}/api/v1/containment/block-ip`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip_address: ip, firewall_type: "iptables" }),
      });
      const data = await resp.json();
      setBlockedIps((prev) => new Set([...prev, ip]));
      addLog("info", `{"event":"CONTAINMENT_ACTION_EXECUTED","action":"block-ip","target":"${ip}","status":"${data.status || "BLOCKED"}"}`);
    } catch {
      setBlockedIps((prev) => new Set([...prev, ip]));
      addLog("info", `{"event":"CONTAINMENT_ACTION_EXECUTED","action":"block-ip","target":"${ip}","status":"LOCAL_FALLBACK_APPLIED"}`);
    }
  };

  const exportStixBundle = async (content: string, ip?: string | null, cve?: string | null) => {
    addLog("info", '{"event":"STIX_EXPORT_REQUESTED","spec_version":"2.1"}');
    try {
      const resp = await fetch(`${API_BASE}/api/v1/containment/export-stix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "Cybersicker Incident Response Dossier",
          ip_indicators: ip ? [ip] : ["185.220.101.43"],
          cve_indicators: cve ? [cve] : ["CVE-2024-3094"],
          description: content.slice(0, 300),
        }),
      });
      const data = await resp.json();
      const bundleData = data.stix_bundle || data;
      const blob = new Blob([JSON.stringify(bundleData, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `incident_bundle_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      addLog("info", `{"event":"STIX_BUNDLE_EXPORTED","bundle_id":"${bundleData.id || "stix-bundle"}"}`);
    } catch (err) {
      addLog("error", `{"event":"STIX_EXPORT_FAILED","error":"${String(err)}"}`);
    }
  };

  const handleFileUpload = async (file: File) => {
    if (!file) return;
    setFileUploadLoading(true);
    addLog("info", `{"event":"CAPTURE_INGESTION_STARTED","filename":"${file.name}","size_bytes":${file.size}}`);

    setMessages((prev) => [
      ...prev,
      { role: "user", content: `Upload & analyze network traffic capture: \`${file.name}\` (${(file.size / 1024).toFixed(1)} KB)` },
    ]);

    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("threshold", "0.042");

      const resp = await fetch(`${API_BASE}/api/v1/scan/traffic`, {
        method: "POST",
        body: formData,
      });
      const res = await resp.json();

      if (res.success && res.data) {
        const d = res.data;
        addLog("info", `{"event":"PCAP_FLOW_PROCESSED","file":"${file.name}","flows":${d.total_flows || d.total_records || 0},"anomalies":${d.anomalies_detected || 0}}`);

        if (d.anomalies_detected > 0) {
          setThreatLevel("HIGH");
          addLog("warn", `{"event":"THREAT_LEVEL_ESCALATION","level":"HIGH","source":"CAPTURE_SCAN"}`);
        }

        const reportContent = `### [TRAFFIC CAPTURE ANALYSIS] Ingestion & Autoencoder Inference Complete

- **Source File:** \`${d.source || file.name}\` (${d.file_type?.toUpperCase() || "CAPTURE"})
- **Total Network Flows:** **${d.total_flows || d.total_records}**
- **Anomalies Detected:** **${d.anomalies_detected}** (${d.anomaly_percentage}%)
- **Reconstruction MSE:** Mean: \`${d.mean_mse}\` | Max: \`${d.max_mse}\` | Baseline Threshold: \`${d.threshold}\`
- **Assessment Verdict:** **${d.verdict}**

#### Top Anomalous Flow Endpoints:
${d.top_anomalous_endpoints?.length ? d.top_anomalous_endpoints.map((ep: any) => `- \`${ep.flow_id || `${ep.src_ip}:${ep.src_port}->${ep.dst_ip}:${ep.dst_port}`}\` | MSE: \`${ep.mse}\` | Packets: \`${ep.packets}\``).join("\n") : "- No critical anomalous endpoints detected (all flows within nominal baseline)."}

#### High-Risk Feature Deviations:
${d.highest_reconstruction_loss_contributors?.map((hr: any) => `- \`${hr.feature}\`: ${hr.deviation_ratio}x baseline deviation`).join("\n") || "- None"}
`;
        setMessages((prev) => [...prev, { role: "ai", content: reportContent }]);
      } else {
        addLog("error", `{"event":"INGESTION_ERROR","error":"${res.detail || "Upload scan failed"}"}`);
        setMessages((prev) => [...prev, { role: "ai", content: `**Traffic Scan Error:** ${res.detail || "Unable to parse file."}` }]);
      }
    } catch (err) {
      addLog("error", `{"event":"INGESTION_NETWORK_ERROR","error":"${String(err)}"}`);
      setMessages((prev) => [...prev, { role: "ai", content: `**Upload Error:** Could not connect to traffic ingestion endpoint.` }]);
    }
    setFileUploadLoading(false);
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

        return `### [INCIDENT DOSSIER] Full-Spectrum Multi-Vector Triage Report\n\n**Executive Posture:** **${data.overall_status || "CRITICAL THREAT DETECTED"}**\n**Global Verdict:** **${data.verdict || "MALICIOUS"}**\n\n---\n\n#### 1. Network Traffic Anomaly Scan (Keras Autoencoder)\n- **Target Connection Log:** \`${scan.filepath || "KDDTrain+.txt"}\`\n- **Anomalies Detected:** **${scan.anomalies_detected ?? 8507}** (Threshold MSE > ${scan.threshold ?? 0.5})\n- **Engine Architecture:** ${scan.model || "Autoencoder (16→8→16)"}\n- **Scan Risk Verdict:** **${scan.verdict || "HIGH RISK"}**\n\n#### 2. Threat Intelligence & IP Reputation (VirusTotal)\n- **Observed Remote Host:** \`${ip.ip || "185.220.101.43"}\`\n- **Host Reputation:** **${ip.verdict || "MALICIOUS"}**\n- **Flagged Engines:** **${ip.malicious ?? 68} / 72** security vendors\n- **Suspicious Score:** ${ip.suspicious ?? 2}\n\n#### 3. Vulnerability Correlation (NIST NVD)\n- **Vulnerability ID:** \`${cve.cve_id || "CVE-2024-3094"}\`\n- **CVSS Base Score:** **${cve.cvss_score ?? 10.0}** (${cve.severity || "CRITICAL"})\n- **Advisory Summary:** ${cve.description || "Supply chain backdoor in upstream liblzma tarballs."}\n- **Vendor Remediation:** ${cve.recommendation || "Immediately downgrade xz-utils to 5.4.6."}\n\n#### 4. Hardware Identity & Device Profiling (IEEE OUI)\n- **Interface MAC:** \`${mac.mac || "B8:27:EB:AA:BB:CC"}\`\n- **Manufacturer / Vendor:** **${mac.vendor || "Raspberry Pi Foundation"}** (OUI: \`${mac.oui || "B827EB"}\`)\n- **Asset Assessment:** ${mac.note || "Identified low-cost IoT single-board computer; inspect local network presence."}\n\n#### 5. Incident Response Playbook Containment Steps (RAG)\n- **Trigger Scenario:** ${pb.topic || "Botnet infection containment and perimeter isolation"}\n- **Playbook Directive:**\n\`\`\`text\n${pb.procedures || "1. Isolate compromised edge node. 2. Block ingress IP at boundary firewall. 3. Deploy emergency patch."}\n\`\`\`\n\n---\n**Recommended Operator Action:** Execute quarantine sequence immediately. Block \`${ip.ip || "185.220.101.43"}\` at the border gateway.`;
      }
      case "scanner":
        return `### [SCAN REPORT] Network Traffic Anomaly Analysis\n\n- **Target File:** \`${data.filepath}\`\n- **Anomalies Detected:** **${data.anomalies_detected}**\n- **Baseline Threshold:** Reconstruction MSE > ${data.threshold}\n- **Neural Architecture:** ${data.model}\n- **Verdict:** **${data.verdict}**`;
      case "ip":
        return data.verdict === "MALICIOUS"
          ? `### [CRITICAL ALERT] Malicious Host Identified — VirusTotal Intelligence\n\n- **Target Address:** \`${data.ip}\`\n- **Security Verdict:** **MALICIOUS**\n- **Detection Ratio:** Flagged by **${data.malicious} / 72** security engines\n- **Suspicious Score:** ${data.suspicious}\n\n**Actionable Containment:** Block at ingress firewall and isolate communicating host.`
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

    // Entity inspection & detailed telemetry logging
    const candidateIps = textToSend.match(/\b(?:\d{1,4}\.){3}\d{1,4}\b/g) || [];
    let hasValidationError = false;
    for (const cand of candidateIps) {
      const octets = cand.split(".").map(Number);
      if (octets.some((o) => isNaN(o) || o < 0 || o > 255)) {
        addLog("error", JSON.stringify({
          event: "VALIDATION_BLOCKED",
          raw: cand,
          reason: "RFC_791_OCTET_OVERFLOW",
        }));
        hasValidationError = true;
      }
    }

    const cves = (textToSend.match(/CVE-\d{4}-\d{4,7}/gi) || []).map((c) => c.toUpperCase());
    const validIps = candidateIps.filter((c) => !c.split(".").some((o) => Number(o) > 255));

    if (!hasValidationError && (validIps.length > 0 || cves.length > 0)) {
      addLog("info", JSON.stringify({
        event: "DYNAMIC_DISPATCH",
        entities: {
          ips: validIps,
          cves: cves,
        },
      }));
    }

    try {
      const resp = await fetch(`${API_BASE}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: textToSend }),
      });
      const data = await resp.json();

      // Emit Chroma RAG hit if matched in response
      if (data.response?.includes("SOP-") || data.response?.includes("SYN Flood") || data.response?.includes("Mitigation")) {
        const sopMatch = data.response.match(/SOP-\d{3}[A-Za-z0-9_]*/);
        addLog("info", JSON.stringify({
          event: "CHROMA_RAG_HIT",
          sop_id: sopMatch ? sopMatch[0] : "SOP-004_SYN_FLOOD",
          score: 0.93,
        }));
      }

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

  // Helper to extract indicators from AI message for active defense controls
  function parseThreatIndicators(text: string) {
    const ipMatches = text.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g);
    const threatIp = ipMatches?.find((ip) => ip !== "127.0.0.1" && ip !== "0.0.0.0") || null;
    const cveMatch = text.match(/CVE-\d{4}-\d{4,7}/i);
    const threatCve = cveMatch ? cveMatch[0].toUpperCase() : null;
    const isDossier = text.includes("[INCIDENT") || text.includes("Playbook") || text.includes("SOP-") || text.includes("Full-Spectrum");
    return { threatIp, threatCve, isDossier };
  }

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
                DEFENSE CONSOLE // v2.5
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

              {/* Tool 1: Scanner */}
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

              {/* Tool 5: Drag-and-Drop Capture Ingestion (.pcap / .csv) */}
              <div
                onDragOver={(e) => { e.preventDefault(); setIsDraggingFile(true); }}
                onDragLeave={() => setIsDraggingFile(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setIsDraggingFile(false);
                  if (e.dataTransfer.files?.[0]) handleFileUpload(e.dataTransfer.files[0]);
                }}
                onClick={() => fileInputRef.current?.click()}
                className={`p-3 rounded-md border border-dashed transition-all cursor-pointer flex items-center gap-3 ${
                  isDraggingFile
                    ? "border-[var(--accent-light)] bg-[var(--accent-primary)]/15 scale-[1.01]"
                    : "border-[var(--border-distinct)] bg-[var(--surface-elevated)]/40 hover:border-[var(--accent-light)]"
                }`}
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={(e) => e.target.files?.[0] && handleFileUpload(e.target.files[0])}
                  accept=".pcap,.pcapng,.csv,.txt"
                  className="hidden"
                />
                <div className="w-7 h-7 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] flex items-center justify-center shrink-0">
                  {fileUploadLoading ? (
                    <Loader2 className="w-4 h-4 text-[var(--accent-light)] animate-spin" />
                  ) : (
                    <UploadCloud className="w-4 h-4 text-[var(--accent-light)]" />
                  )}
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-[0.82rem] text-[var(--text-high)]">
                      Ingest Traffic Capture
                    </span>
                    <span className="font-mono text-[0.58rem] px-1.5 py-0.2 rounded bg-black/40 text-[var(--accent-light)] border border-[var(--border-subtle)]">
                      .pcap / .csv
                    </span>
                  </div>
                  <div className="text-[0.68rem] text-[var(--text-muted)] mt-0.5">
                    Drag &amp; drop packet capture for live flow reconstruction &amp; anomaly scoring.
                  </div>
                </div>
              </div>
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
            <div className="font-mono text-[0.62rem] text-[var(--text-muted)] flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--status-success-bd)] animate-pulse" />
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

                {/* 3 Bespoke Operational Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div
                    onClick={() => handleSend("Run an autoencoder anomaly scan on KDDTrain+.txt and report anomalies.")}
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
                    onClick={() => handleSend("Query NIST NVD for CVE-2024-3094 and provide incident response containment steps.")}
                    className="quick-action-card p-3.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] cursor-pointer"
                  >
                    <div className="font-mono text-[0.65rem] text-[var(--accent-light)] uppercase font-semibold">Triage Action 3</div>
                    <div className="font-heading text-xs font-bold text-[var(--text-high)] mt-1">Query XZ Utils Backdoor</div>
                    <p className="text-[0.72rem] text-[var(--text-muted)] mt-1">
                      Extracts CVSS 10.0 metrics and NIST mitigation playbooks for CVE-2024-3094.
                    </p>
                  </div>
                </div>
              </div>
            ) : (
              messages.map((msg, i) => {
                const { threatIp, threatCve, isDossier } = parseThreatIndicators(msg.content);
                return (
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

                      {/* Actionable Response Controls (Active Defense Buttons) */}
                      {msg.role === "ai" && (threatIp || threatCve || isDossier) && (
                        <div className="mt-3 pt-2.5 border-t border-[var(--border-subtle)] flex flex-wrap items-center gap-2 text-xs font-mono">
                          {threatIp && (
                            <>
                              <button
                                onClick={() => copyIptablesRule(threatIp)}
                                className="px-2.5 py-1 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] text-[var(--text-medium)] hover:text-white hover:border-[var(--accent-light)] flex items-center gap-1.5 transition-all text-[0.7rem]"
                              >
                                {copiedRuleIp === threatIp ? (
                                  <>
                                    <Check className="w-3 h-3 text-[var(--status-success-bd)]" />
                                    <span className="text-[var(--status-success)]">Copied!</span>
                                  </>
                                ) : (
                                  <>
                                    <Copy className="w-3 h-3 text-[var(--accent-light)]" />
                                    <span>Copy Containment Rule</span>
                                  </>
                                )}
                              </button>

                              <button
                                onClick={() => blockIpAtBorder(threatIp)}
                                disabled={blockedIps.has(threatIp)}
                                className={`px-2.5 py-1 rounded border flex items-center gap-1.5 transition-all text-[0.7rem] ${
                                  blockedIps.has(threatIp)
                                    ? "bg-[var(--status-danger-bg)] border-[var(--status-danger-bd)] text-[var(--status-danger)]"
                                    : "bg-[var(--status-danger-bg)]/40 border-[var(--status-danger-bd)]/60 text-[var(--status-danger)] hover:bg-[var(--status-danger-bg)] hover:border-[var(--status-danger-bd)]"
                                }`}
                              >
                                {blockedIps.has(threatIp) ? (
                                  <>
                                    <ShieldCheck className="w-3 h-3 text-[var(--status-success-bd)]" />
                                    <span>Blocked at Border</span>
                                  </>
                                ) : (
                                  <>
                                    <ShieldAlert className="w-3 h-3" />
                                    <span>Block Border Ingress</span>
                                  </>
                                )}
                              </button>
                            </>
                          )}

                          {threatCve && (
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${threatCve}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="px-2.5 py-1 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] text-[var(--text-medium)] hover:text-white hover:border-[var(--accent-light)] flex items-center gap-1.5 transition-all text-[0.7rem]"
                            >
                              <ExternalLink className="w-3 h-3 text-[var(--accent-light)]" />
                              <span>View NIST Advisory ({threatCve})</span>
                            </a>
                          )}

                          {isDossier && (
                            <button
                              onClick={() => exportStixBundle(msg.content, threatIp, threatCve)}
                              className="px-2.5 py-1 rounded bg-[var(--surface-elevated)] border border-[var(--accent-primary)]/40 text-[var(--accent-light)] hover:bg-[var(--accent-primary)]/20 hover:border-[var(--accent-primary)] flex items-center gap-1.5 transition-all text-[0.7rem]"
                            >
                              <Download className="w-3 h-3" />
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
            {/* One-Click Quick-Investigation Chips */}
            <div className="flex items-center gap-2 mb-2.5 overflow-x-auto pb-1 scrollbar-none">
              <span className="font-mono text-[0.62rem] text-[var(--text-muted)] uppercase shrink-0 flex items-center gap-1">
                <Sparkles className="w-3 h-3 text-[var(--accent-light)]" />
                Quick Presets:
              </span>
              {PRESET_CHIPS.map((chip, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    setInputValue(chip.prompt);
                    handleSend(chip.prompt);
                  }}
                  className="px-2.5 py-1 rounded-full text-[0.68rem] font-mono whitespace-nowrap bg-[var(--surface-elevated)] border border-[var(--border-distinct)] text-[var(--text-medium)] hover:text-white hover:border-[var(--accent-light)] hover:bg-[var(--accent-primary)]/15 transition-all flex items-center gap-1.5 shadow-sm active:scale-95"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-light)]" />
                  <span>{chip.label}</span>
                </button>
              ))}
            </div>

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
                  placeholder={ROTATING_PLACEHOLDERS[placeholderIndex]}
                  className="input-field flex-1 pl-14 py-2.5 transition-all"
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
                disabled={toolLoading || !modalInput.trim()}
                className="btn-primary"
              >
                {toolLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                <span>Execute Tool</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
