"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import {
  Shield,
  Wifi,
  AlertTriangle,
  Clock,
  Radar,
  Globe,
  Fingerprint,
  Bug,
  Send,
  Terminal,
  Activity,
  ShieldCheck,
  ChevronRight,
  Zap,
  Loader2,
  X,
} from "lucide-react";

const API_BASE = "http://localhost:8000";
const DEBUG_ENDPOINT = "http://127.0.0.1:7894/ingest/96ebdde3-7662-4c1f-803f-ba6b12bf6c5d";

function debugLog(hypothesisId: string, location: string, message: string, data: Record<string, unknown>) {
  // #region agent log
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
  // #endregion
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
} | null;

const TOOL_CONFIGS: Record<string, ToolModalConfig> = {
  scanner: {
    tool: "scanner",
    label: "Network Scanner — Enter file path",
    placeholder: "D:\\CYBERSICKER\\KDDTrain+.txt",
    endpoint: "/api/tools/scan",
    bodyKey: "filepath",
},
  ip: {
    tool: "ip",
    label: "IP Check — Enter IPv4 address",
    placeholder: "185.220.101.43",
    endpoint: "/api/tools/ip-check",
    bodyKey: "ip_address",
},
  mac: {
    tool: "mac",
    label: "MAC Lookup — Enter MAC address",
    placeholder: "AA:BB:CC:DD:EE:FF",
    endpoint: "/api/tools/mac-lookup",
    bodyKey: "mac_address",
},
  cve: {
    tool: "cve",
    label: "CVE Database — Enter CVE ID",
    placeholder: "CVE-2021-44228",
    endpoint: "/api/tools/cve-lookup",
    bodyKey: "cve_id",
},
};

/* ═══════════════════════════════════════════
   COMPONENT
   ═══════════════════════════════════════════ */

export default function Dashboard() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState("");
  const [uptime, setUptime] = useState({ h: 0, m: 0, s: 0 });
  const [sensorCount, setSensorCount] = useState(48);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [chatLoading, setChatLoading] = useState(false);
  const [toolLoading, setToolLoading] = useState(false);
  const [activeModal, setActiveModal] = useState<ToolModalConfig>(null);
  const [modalInput, setModalInput] = useState("");
  const [threatLevel, setThreatLevel] = useState<"LOW" | "MONITORING" | "HIGH">("MONITORING");
  const [apiStatus, setApiStatus] = useState<"checking" | "online" | "offline">("checking");

  const chatEndRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<HTMLDivElement>(null);

  // ─── Helpers ──────────────────────────────
  function now() {
    const d = new Date();
    return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}:${d.getSeconds().toString().padStart(2, "0")}`;
  }

  const addLog = useCallback((level: "info" | "warn" | "error", msg: string) => {
    setLogs((prev) => [...prev.slice(-50), { ts: now(), level, msg }]);
}, []);

  // ─── Initial boot log (client-only) ───────
  useEffect(() => {
    addLog("info", '{"event":"SYSTEM_BOOT","status":"SOC_ONLINE","version":"2.0"}');
}, [addLog]);

  // ─── Health check ─────────────────────────
  useEffect(() => {
    debugLog("H1", "app/page.tsx:health-check:start", "Starting health check", {
      apiBase: API_BASE,
      target: `${API_BASE}/api/health`,
      online: typeof navigator !== "undefined" ? navigator.onLine : null,
    });
    fetch(`${API_BASE}/api/health`)
      .then((r) => r.json())
      .then((d) => {
        debugLog("H1", "app/page.tsx:health-check:success", "Health check succeeded", {
          googleKeySet: d.google_key_set,
          vtKeySet: d.vt_key_set,
        });
        setApiStatus("online");
        addLog("info", `{"event":"API_CONNECTED","google_key":${d.google_key_set},"vt_key":${d.vt_key_set}}`);
    })
      .catch((err: unknown) => {
        debugLog("H1", "app/page.tsx:health-check:error", "Health check failed", {
          error: err instanceof Error ? err.message : String(err),
          online: typeof navigator !== "undefined" ? navigator.onLine : null,
          target: `${API_BASE}/api/health`,
        });
        setApiStatus("offline");
        addLog("error", '{"event":"API_OFFLINE","msg":"Backend at localhost:8000 unreachable"}');
    });
}, [addLog]);

  // ─── Uptime ticker ────────────────────────
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

  // ─── Sensor flicker ──────────────────────
  useEffect(() => {
    const interval = setInterval(() => {
      setSensorCount((p) => Math.max(40, Math.min(56, p + (Math.random() > 0.5 ? 1 : -1))));
  }, 3000);
    return () => clearInterval(interval);
}, []);

  // ─── Auto-scroll ──────────────────────────
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
}, [messages]);

  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
}, [logs]);

  // ─── Tool Execution ──────────────────────
  const runTool = async (config: NonNullable<ToolModalConfig>, inputVal: string) => {
    setToolLoading(true);
    setActiveModal(null);
    debugLog("H2", "app/page.tsx:runTool:start", "Tool invocation started", {
      tool: config.tool,
      endpoint: `${API_BASE}${config.endpoint}`,
      bodyKey: config.bodyKey,
    });
    addLog("info", `{"event":"TOOL_INVOKE","tool":"${config.tool}","input":"${inputVal}"}`);

    try {
      const resp = await fetch(`${API_BASE}${config.endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ [config.bodyKey]: inputVal }),
    });
      const data = await resp.json();

      if (data.success) {
        const parsed = JSON.parse(data.result);
        addLog("info", data.result);

        // Update threat level based on results
        if (parsed.verdict === "MALICIOUS" || parsed.verdict === "HIGH RISK") {
          setThreatLevel("HIGH");
          addLog("error", `{"event":"THREAT_ESCALATION","level":"HIGH","source":"${config.tool}"}`);
        }

        // Add result to chat as AI message
        setMessages((prev) => [
          ...prev,
          { role: "ai", content: formatToolResult(config.tool, parsed) },
        ]);
    } else {
        addLog("error", `{"event":"TOOL_ERROR","tool":"${config.tool}","error":"${data.result}"}`);
        setMessages((prev) => [
          ...prev,
          { role: "ai", content: `❌ **Tool Error:** ${data.result}` },
        ]);
      }
  } catch (e) {
      debugLog("H2", "app/page.tsx:runTool:error", "Tool invocation failed", {
        tool: config.tool,
        endpoint: `${API_BASE}${config.endpoint}`,
        error: e instanceof Error ? e.message : String(e),
        online: typeof navigator !== "undefined" ? navigator.onLine : null,
      });
      addLog("error", `{"event":"TOOL_ERROR","tool":"${config.tool}","error":"Network error"}`);
      setMessages((prev) => [
        ...prev,
        { role: "ai", content: "❌ **Connection Error:** Could not reach the backend API. Make sure the FastAPI server is running on port 8000." },
      ]);
    }
    setToolLoading(false);
};

  // ─── Format tool results nicely ───────────
  function formatToolResult(tool: string, data: Record<string, unknown>): string {
    switch (tool) {
      case "scanner":
        return `🔒 **Network Scan Complete**\n\n- **File:** \`${data.filepath}\`\n- **Anomalies Detected:** ${data.anomalies_detected}\n- **Threshold:** MSE > ${data.threshold}\n- **Model:** ${data.model}\n- **Verdict:** ${data.verdict}`;
      case "ip":
        return data.verdict === "MALICIOUS"
          ? `🚨 **CRITICAL ALERT — VirusTotal**\n\n- **IP:** \`${data.ip}\`\n- **Verdict:** MALICIOUS\n- **Flagged by:** ${data.malicious} security vendors\n- **Suspicious:** ${data.suspicious}\n\n⚠️ Block at perimeter firewall and isolate any IoT device that communicated with this address.`
          : `✅ **IP Clean — VirusTotal**\n\n- **IP:** \`${data.ip}\`\n- **Verdict:** CLEAN\n- **Malicious:** 0 vendors flagged`;
      case "mac":
        return `📡 **MAC Address Lookup**\n\n- **MAC:** \`${data.mac}\`\n- **OUI:** ${data.oui}\n- **Vendor:** ${data.vendor}\n- **Note:** ${data.note}`;
      case "cve":
        return data.found
          ? `🐛 **CVE Report — ${data.cve_id}**\n\n- **Published:** ${data.published}\n- **CVSS Score:** ${data.cvss_score} (${data.severity})\n- **Description:** ${(data.description as string)?.slice(0, 300)}...\n- **Recommendation:** ${data.recommendation}`
          : `ℹ️ **CVE Not Found:** \`${data.cve_id}\` was not found in the NVD database.`;
      default:
        return `\`\`\`json\n${JSON.stringify(data, null, 2)}\n\`\`\``;
  }
}

  // ─── Chat Send ────────────────────────────
  const handleSend = async () => {
    if (!inputValue.trim() || chatLoading) return;
    const userMsg = inputValue.trim();
    setInputValue("");
    setMessages((prev) => [...prev, { role: "user", content: userMsg }]);
    setChatLoading(true);
    debugLog("H3", "app/page.tsx:chat:start", "Chat request started", {
      endpoint: `${API_BASE}/api/chat`,
      promptLength: userMsg.length,
    });
    addLog("info", `{"event":"AGENT_QUERY","prompt":"${userMsg.slice(0, 60)}"}`);

    try {
      const resp = await fetch(`${API_BASE}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: userMsg }),
    });
      const data = await resp.json();
      addLog("info", '{"event":"AGENT_RESPONSE","status":"complete"}');
      setMessages((prev) => [
        ...prev,
        { role: "ai", content: data.success ? data.response : `❌ **Error:** ${data.response}` },
      ]);
    } catch (err: unknown) {
      debugLog("H3", "app/page.tsx:chat:error", "Chat request failed", {
        endpoint: `${API_BASE}/api/chat`,
        error: err instanceof Error ? err.message : String(err),
        online: typeof navigator !== "undefined" ? navigator.onLine : null,
      });
      addLog("error", '{"event":"AGENT_ERROR","msg":"Backend unreachable"}');
      setMessages((prev) => [
        ...prev,
        { role: "ai", content: "❌ **Connection Error:** Could not reach the backend API. Make sure the FastAPI server is running on port 8000." },
      ]);
    }
    setChatLoading(false);
  };

  const pad = (n: number) => n.toString().padStart(2, "0");

  const METRICS = [
    {
      label: "SYSTEM STATUS",
      value: apiStatus === "online" ? "ONLINE" : apiStatus === "offline" ? "OFFLINE" : "...",
      delta: apiStatus === "online" ? "All Systems Nominal" : apiStatus === "offline" ? "API Unreachable" : "Checking...",
      icon: ShieldCheck,
      accent: apiStatus === "offline" ? "accent-left-red" : "accent-left-green",
      shadow: apiStatus === "offline" ? "float-shadow-red" : "float-shadow-green",
      valueColor: apiStatus === "offline" ? "text-red" : "text-green",
      deltaColor: apiStatus === "offline" ? "text-red-dim" : "text-green-dim",
    },
    {
      label: "ACTIVE SENSORS",
      value: sensorCount.toString(),
      delta: "IoT Endpoints",
      icon: Wifi,
      accent: "accent-left-cyan",
      shadow: "float-shadow-cyan",
      valueColor: "text-cyan",
      deltaColor: "text-cyan-dim",
    },
    {
      label: "THREAT LEVEL",
      value: threatLevel,
      delta: threatLevel === "HIGH" ? "Active Alerts" : threatLevel === "MONITORING" ? "Scanning" : "Clear",
      icon: AlertTriangle,
      accent: threatLevel === "HIGH" ? "accent-left-red" : "accent-left-amber",
      shadow: threatLevel === "HIGH" ? "float-shadow-red" : "float-shadow-cyan",
      valueColor: threatLevel === "HIGH" ? "text-red" : "text-amber",
      deltaColor: threatLevel === "HIGH" ? "text-red-dim" : "text-amber",
    },
    {
      label: "UPTIME",
      value: `${pad(uptime.h)}:${pad(uptime.m)}:${pad(uptime.s)}`,
      delta: "Session Active",
      icon: Clock,
      accent: "accent-left-amber",
      shadow: "float-shadow-cyan",
      valueColor: "text-cyan",
      deltaColor: "text-amber",
    },
  ];

  const TOOLS = [
  { key: "scanner", label: "Network Scanner", icon: Radar, desc: "Autoencoder Scan" },
  { key: "ip", label: "IP Check", icon: Globe, desc: "VirusTotal Intel" },
  { key: "mac", label: "MAC Lookup", icon: Fingerprint, desc: "Device Vendor ID" },
  { key: "cve", label: "CVE Database", icon: Bug, desc: "NIST NVD Query" },
  ];

  return (
    <div className="min-h-screen px-4 py-3 md:px-6 lg:px-8 max-w-[1440px] mx-auto flex flex-col gap-4">
    {/* ═══════════ SOC STATUS BANNER (Sandbox Mode) ═══════════ */}
    {apiStatus === "online" && (
        <div className="glass-strong border-amber/30 bg-amber/5 px-4 py-2 flex flex-col sm:flex-row items-center justify-between gap-3 animate-fade-in-up">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-amber/20 border border-amber/40">
              <Zap className="w-4 h-4 text-amber animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-display text-[0.65rem] font-bold tracking-[2px] text-amber uppercase">SOC Sandbox Mode Active</span>
                <span className="h-1 w-1 rounded-full bg-amber/60" />
                <span className="text-[0.6rem] text-amber/80 font-medium uppercase tracking-wider">Operational Limited</span>
              </div>
              <p className="text-[0.55rem] text-text-muted uppercase tracking-widest mt-0.5">
                Local ML Tools Operational <span className="text-amber/40 mx-1">|</span> AI Agent in Simulated Mode
              </p>
            </div>
          </div>
          <button 
            onClick={() => window.alert("Configure API keys in .env to enable Elite Autonomous mode.")}
            className="group flex items-center gap-2 px-3 py-1.5 bg-amber/10 hover:bg-amber/20 border border-amber/30 hover:border-amber/50 rounded-md transition-all duration-300"
            suppressHydrationWarning
          >
            <Shield className="w-3 h-3 text-amber group-hover:scale-110 transition-transform" />
            <span className="text-[0.6rem] font-bold text-amber tracking-widest uppercase">Configure API</span>
          </button>
        </div>
      )}

    {/* ═══════════ TOOL INPUT MODAL ═══════════ */}
    {activeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="glass-strong float-shadow-cyan p-6 w-full max-w-md mx-4 animate-fade-in-up">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-display text-xs font-semibold tracking-[2px] text-cyan uppercase">
              {activeModal.label}
              </h3>
              <button onClick={() => setActiveModal(null)} className="text-text-muted hover:text-red transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
            <input
              type="text"
              autoFocus
              suppressHydrationWarning
              value={modalInput}
              onChange={(e) => setModalInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && modalInput.trim()) runTool(activeModal, modalInput.trim());
              }}
              placeholder={activeModal.placeholder}
              className="input-glow w-full px-4 py-2.5 text-[0.82rem] mb-4"
            />
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setActiveModal(null)}
                className="px-4 py-2 text-[0.72rem] text-text-muted hover:text-text transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => { if (modalInput.trim()) runTool(activeModal, modalInput.trim()); }}
                className="btn-send flex items-center gap-2"
                suppressHydrationWarning
              >
                <Zap className="w-3.5 h-3.5" />
                Execute
              </button>
            </div>
          </div>
        </div>
      )}

    {/* ═══════════ HEADER ═══════════ */}
      <header className="glass-strong float-shadow-cyan px-5 py-4 md:px-8 md:py-5 flex items-center justify-between relative overflow-hidden animate-fade-in-up">
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan to-transparent opacity-60" />
        <div className="flex items-center gap-4">
          <div className="w-11 h-11 md:w-14 md:h-14 rounded-xl bg-cyan-muted border border-border-active flex items-center justify-center flex-shrink-0 overflow-hidden">
            <img src="/logo.png" alt="CYBERSICKER Logo" className="w-full h-full object-cover" />
          </div>
          <div>
            <h1 className="font-display text-xl md:text-2xl lg:text-3xl font-bold tracking-[3px] text-cyan drop-shadow-[0_0_20px_rgba(0,240,255,0.3)]">
              CYBERSICKER
            </h1>
            <p className="text-[0.6rem] md:text-[0.7rem] text-text-muted tracking-[2px] uppercase mt-0.5">
              Autonomous IoT Blue Team Agent — Threat Detection & Response
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="hidden md:flex items-center gap-2 text-[0.65rem] text-text-muted tracking-wider">
            <Activity className="w-3.5 h-3.5 text-green animate-glow" />
            <span>LIVE</span>
          </div>
          <div className="animate-pulse-badge bg-red text-white text-[0.6rem] md:text-[0.65rem] font-semibold px-3 py-1.5 md:px-4 md:py-1.5 rounded-full tracking-[2px] uppercase font-display flex items-center gap-2">
            <Zap className="w-3 h-3" />
            SOC ACTIVE
          </div>
        </div>
        <div className="absolute top-0 left-[-100%] w-full h-full bg-gradient-to-r from-transparent via-cyan/[0.03] to-transparent animate-scanline pointer-events-none" />
      </header>

    {/* ═══════════ METRIC CARDS ═══════════ */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 md:gap-4">
      {METRICS.map((m, i) => (
          <div key={m.label} className={`glass-card ${m.accent} ${m.shadow} px-4 py-4 md:px-5 md:py-5 animate-fade-in-up`} style={{ animationDelay: `${i * 80}ms` }}>
            <div className="flex items-start justify-between mb-3">
              <span className="text-[0.6rem] text-text-muted tracking-[1.5px] uppercase font-medium">{m.label}</span>
              <m.icon className={`w-4 h-4 ${m.valueColor} opacity-60`} />
            </div>
            <div className={`font-display text-xl md:text-2xl font-bold ${m.valueColor} tracking-wider`}>{m.value}</div>
            <div className={`text-[0.6rem] ${m.deltaColor} mt-1.5 flex items-center gap-1`}>
              <ChevronRight className="w-3 h-3" />
            {m.delta}
            </div>
          </div>
        ))}
      </div>

    {/* ═══════════ MAIN CONTENT ═══════════ */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 md:gap-5 flex-1 min-h-0">
      {/* ── LEFT COLUMN ── */}
        <div className="lg:col-span-4 flex flex-col gap-4">
        {/* Tool Buttons */}
          <div className="glass-strong float-shadow-cyan p-4 md:p-5 animate-fade-in-up" style={{ animationDelay: "250ms" }}>
            <div className="flex items-center gap-2 mb-4">
              <Terminal className="w-4 h-4 text-cyan opacity-70" />
              <h2 className="font-display text-[0.7rem] md:text-xs font-semibold tracking-[2px] text-cyan uppercase">Agent Tools</h2>
            {toolLoading && <Loader2 className="w-3.5 h-3.5 text-cyan animate-spin ml-auto" />}
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-1 gap-2">
            {TOOLS.map((tool) => (
                <button
                  key={tool.key}
                  disabled={toolLoading}
                  suppressHydrationWarning
                  onClick={() => {
                    const config = TOOL_CONFIGS[tool.key];
                    if (config) {
                      setModalInput(config.placeholder);
                      setActiveModal(config);
                    }
                  }}
                  className="btn-tool group disabled:opacity-40 disabled:cursor-wait"
                >
                  <tool.icon className="w-4 h-4 flex-shrink-0 opacity-70 group-hover:opacity-100 transition-opacity" />
                  <div className="text-left">
                    <div>{tool.label}</div>
                    <div className="text-[0.58rem] text-text-muted mt-0.5 group-hover:text-cyan-dim transition-colors">{tool.desc}</div>
                  </div>
                </button>
              ))}
            </div>
          </div>

        {/* Terminal Log */}
          <div className="glass-strong float-shadow-cyan p-4 md:p-5 flex-1 flex flex-col min-h-[280px] animate-fade-in-up" style={{ animationDelay: "350ms" }}>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className="flex gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-red/60" />
                  <span className="w-2.5 h-2.5 rounded-full bg-amber/60" />
                  <span className="w-2.5 h-2.5 rounded-full bg-green/60" />
                </div>
                <h2 className="font-display text-[0.65rem] md:text-[0.7rem] font-semibold tracking-[2px] text-cyan uppercase">System Logs</h2>
              </div>
              <span className="text-[0.55rem] text-text-muted tracking-wider">LIVE FEED</span>
            </div>
            <div ref={terminalRef} className="flex-1 overflow-y-auto bg-black/30 rounded-lg p-3 terminal-log">
            {logs.map((log, i) => (
                <div key={i} className="flex gap-2 py-0.5">
                  <span className="log-timestamp shrink-0">{log.ts}</span>
                  <span className={`shrink-0 ${log.level === "error" ? "log-error" : log.level === "warn" ? "log-warn" : "log-info"}`}>
                  {log.level === "error" ? "ERR" : log.level === "warn" ? "WRN" : "INF"}
                  </span>
                  <span className="opacity-70 break-all">{log.msg}</span>
                </div>
              ))}
              <div className="flex items-center gap-1 mt-1 text-cyan-dim animate-glow"><span>█</span></div>
            </div>
          </div>
        </div>

      {/* ── RIGHT COLUMN: AI Agent Chat ── */}
        <div className="lg:col-span-8 glass-strong float-shadow-cyan flex flex-col min-h-[500px] lg:min-h-0 animate-fade-in-up" style={{ animationDelay: "200ms" }}>
        {/* Chat Header */}
          <div className="px-5 py-4 border-b border-border flex items-center justify-between shrink-0">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-cyan-muted border border-border-active flex items-center justify-center">
                <Shield className="w-4 h-4 text-cyan" />
              </div>
              <div>
                <h2 className="font-display text-[0.7rem] md:text-xs font-semibold tracking-[2px] text-cyan uppercase">Cybersicker Agent</h2>
                <p className="text-[0.55rem] text-green flex items-center gap-1 mt-0.5">
                  <span className={`w-1.5 h-1.5 rounded-full ${apiStatus === "online" ? "bg-green animate-glow" : "bg-red"} inline-block`} />
                {apiStatus === "online" ? "Online — Gemini 2.5 Flash" : "Offline — Backend Unreachable"}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 text-[0.6rem] text-text-muted">
              <Activity className="w-3 h-3" />
              <span className="hidden sm:inline">Threat Intel Protocol Active</span>
            </div>
          </div>

        {/* Chat Messages */}
          <div className="flex-1 overflow-y-auto px-4 py-4 md:px-5 space-y-3">
            <div className="text-center py-2">
              <span className="text-[0.58rem] text-text-muted bg-bg-card-solid px-3 py-1 rounded-full tracking-wider">
                SESSION INITIATED — CYBERSICKER SOC v2.0
              </span>
            </div>

          {messages.length === 0 && (
              <div className="text-center py-12">
                <Shield className="w-12 h-12 text-cyan/20 mx-auto mb-3" />
                <p className="text-[0.75rem] text-text-muted">Use the Agent Tools or type a command below to begin.</p>
                <p className="text-[0.6rem] text-text-muted/60 mt-1">Try: &quot;Scan KDDTrain+.txt&quot; or &quot;Check IP 185.220.101.43&quot;</p>
              </div>
            )}

          {messages.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                <div className={`max-w-[85%] md:max-w-[75%] px-4 py-3 ${msg.role === "user" ? "chat-bubble-user" : "chat-bubble-ai"}`}>
                  <div className={`text-[0.55rem] font-semibold tracking-[1.5px] uppercase mb-1.5 ${msg.role === "user" ? "text-cyan-dim" : "text-green-dim"}`}>
                  {msg.role === "user" ? "👤 OPERATOR" : "🛡️ CYBERSICKER"}
                  </div>
                  <div className="text-[0.78rem] md:text-[0.82rem] leading-relaxed text-text whitespace-pre-wrap">
                  {msg.content.split(/(\*\*.*?\*\*|`.*?`)/g).map((part, j) => {
                      if (part.startsWith("**") && part.endsWith("**"))
                        return <strong key={j} className="text-cyan font-semibold">{part.slice(2, -2)}</strong>;
                      if (part.startsWith("`") && part.endsWith("`"))
                        return <code key={j} className="bg-black/40 text-green px-1.5 py-0.5 rounded text-[0.72rem]">{part.slice(1, -1)}</code>;
                      return <span key={j}>{part}</span>;
                  })}
                  </div>
                </div>
              </div>
            ))}

          {chatLoading && (
              <div className="flex justify-start">
                <div className="chat-bubble-ai px-4 py-3 flex items-center gap-2">
                  <Loader2 className="w-4 h-4 text-cyan animate-spin" />
                  <span className="text-[0.75rem] text-text-muted">Cybersicker is analyzing...</span>
                </div>
              </div>
            )}

            <div ref={chatEndRef} />
          </div>

        {/* Chat Input */}
          <div className="px-4 py-3 md:px-5 md:py-4 border-t border-border shrink-0">
            <div className="flex gap-2 md:gap-3">
              <input
                type="text"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSend()}
                placeholder="Enter a command for Cybersicker..."
                className="input-glow flex-1 px-4 py-2.5 text-[0.8rem]"
                disabled={chatLoading}
                suppressHydrationWarning
              />
              <button onClick={handleSend} disabled={chatLoading} className="btn-send flex items-center gap-2 disabled:opacity-40" suppressHydrationWarning>
              {chatLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                <span className="hidden sm:inline">Send</span>
              </button>
            </div>
          </div>
        </div>
      </div>

    {/* ═══════════ FOOTER ═══════════ */}
      <footer className="text-center py-4 animate-fade-in-up" style={{ animationDelay: "500ms" }}>
        <div className="text-[0.58rem] text-text-muted tracking-[2px] uppercase">
          Powered by{" "}
          <span className="text-cyan-dim font-medium">Vrishin Ram K</span>
        </div>
      </footer>
    </div>
  );
}
