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
  ***REMOVED***,
    body: JSON.stringify({
      sessionId: "dc3fd7",
      runId: "initial",
      hypothesisId,
      location,
      message,
      data,
      timestamp: Date.now(),
  ***REMOVED***),
***REMOVED***).catch(() => {});
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
***REMOVED***,
  ip: {
    tool: "ip",
    label: "IP Check — Enter IPv4 address",
    placeholder: "185.220.101.43",
    endpoint: "/api/tools/ip-check",
    bodyKey: "ip_address",
***REMOVED***,
  mac: {
    tool: "mac",
    label: "MAC Lookup — Enter MAC address",
    placeholder: "AA:BB:CC:DD:EE:FF",
    endpoint: "/api/tools/mac-lookup",
    bodyKey: "mac_address",
***REMOVED***,
  cve: {
    tool: "cve",
    label: "CVE Database — Enter CVE ID",
    placeholder: "CVE-2021-44228",
    endpoint: "/api/tools/cve-lookup",
    bodyKey: "cve_id",
***REMOVED***,
};

/* ═══════════════════════════════════════════
   COMPONENT
   ═══════════════════════════════════════════ */

export default function Dashboard() {
  const ***REMOVED***messages, setMessages***REMOVED*** = useState<ChatMessage***REMOVED******REMOVED***>(***REMOVED******REMOVED***);
  const ***REMOVED***inputValue, setInputValue***REMOVED*** = useState("");
  const ***REMOVED***uptime, setUptime***REMOVED*** = useState({ h: 0, m: 0, s: 0 });
  const ***REMOVED***sensorCount, setSensorCount***REMOVED*** = useState(48);
  const ***REMOVED***logs, setLogs***REMOVED*** = useState<LogEntry***REMOVED******REMOVED***>(***REMOVED******REMOVED***);
  const ***REMOVED***chatLoading, setChatLoading***REMOVED*** = useState(false);
  const ***REMOVED***toolLoading, setToolLoading***REMOVED*** = useState(false);
  const ***REMOVED***activeModal, setActiveModal***REMOVED*** = useState<ToolModalConfig>(null);
  const ***REMOVED***modalInput, setModalInput***REMOVED*** = useState("");
  const ***REMOVED***threatLevel, setThreatLevel***REMOVED*** = useState<"LOW" | "MONITORING" | "HIGH">("MONITORING");
  const ***REMOVED***apiStatus, setApiStatus***REMOVED*** = useState<"checking" | "online" | "offline">("checking");

  const chatEndRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<HTMLDivElement>(null);

  // ─── Helpers ──────────────────────────────
  function now() {
    const d = new Date();
    return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}:${d.getSeconds().toString().padStart(2, "0")}`;
***REMOVED***

  const addLog = useCallback((level: "info" | "warn" | "error", msg: string) => {
    setLogs((prev) => ***REMOVED***...prev.slice(-50), { ts: now(), level, msg }***REMOVED***);
***REMOVED***, ***REMOVED******REMOVED***);

  // ─── Initial boot log (client-only) ───────
  useEffect(() => {
    addLog("info", '{"event":"SYSTEM_BOOT","status":"SOC_ONLINE","version":"2.0"}');
***REMOVED***, ***REMOVED***addLog***REMOVED***);

  // ─── Health check ─────────────────────────
  useEffect(() => {
    debugLog("H1", "app/page.tsx:health-check:start", "Starting health check", {
      apiBase: API_BASE,
      target: `${API_BASE}/api/health`,
      online: typeof navigator !== "undefined" ? navigator.onLine : null,
  ***REMOVED***);
    fetch(`${API_BASE}/api/health`)
      .then((r) => r.json())
      .then((d) => {
        debugLog("H1", "app/page.tsx:health-check:success", "Health check succeeded", {
          googleKeySet: d.google_key_set,
          vtKeySet: d.vt_key_set,
      ***REMOVED***);
        setApiStatus("online");
        addLog("info", `{"event":"API_CONNECTED","google_key":${d.google_key_set},"vt_key":${d.vt_key_set}}`);
    ***REMOVED***)
      .catch((err: unknown) => {
        debugLog("H1", "app/page.tsx:health-check:error", "Health check failed", {
          error: err instanceof Error ? err.message : String(err),
          online: typeof navigator !== "undefined" ? navigator.onLine : null,
          target: `${API_BASE}/api/health`,
      ***REMOVED***);
        setApiStatus("offline");
        addLog("error", '{"event":"API_OFFLINE","msg":"Backend at localhost:8000 unreachable"}');
    ***REMOVED***);
***REMOVED***, ***REMOVED***addLog***REMOVED***);

  // ─── Uptime ticker ────────────────────────
  useEffect(() => {
    const start = Date.now();
    const timer = setInterval(() => {
      const elapsed = Math.floor((Date.now() - start) / 1000);
      setUptime({
        h: Math.floor(elapsed / 3600),
        m: Math.floor((elapsed % 3600) / 60),
        s: elapsed % 60,
    ***REMOVED***);
  ***REMOVED***, 1000);
    return () => clearInterval(timer);
***REMOVED***, ***REMOVED******REMOVED***);

  // ─── Sensor flicker ──────────────────────
  useEffect(() => {
    const interval = setInterval(() => {
      setSensorCount((p) => Math.max(40, Math.min(56, p + (Math.random() > 0.5 ? 1 : -1))));
  ***REMOVED***, 3000);
    return () => clearInterval(interval);
***REMOVED***, ***REMOVED******REMOVED***);

  // ─── Auto-scroll ──────────────────────────
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
***REMOVED***, ***REMOVED***messages***REMOVED***);

  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
***REMOVED***, ***REMOVED***logs***REMOVED***);

  // ─── Tool Execution ──────────────────────
  const runTool = async (config: NonNullable<ToolModalConfig>, inputVal: string) => {
    setToolLoading(true);
    setActiveModal(null);
    debugLog("H2", "app/page.tsx:runTool:start", "Tool invocation started", {
      tool: config.tool,
      endpoint: `${API_BASE}${config.endpoint}`,
      bodyKey: config.bodyKey,
  ***REMOVED***);
    addLog("info", `{"event":"TOOL_INVOKE","tool":"${config.tool}","input":"${inputVal}"}`);

    try {
      const resp = await fetch(`${API_BASE}${config.endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ***REMOVED***config.bodyKey***REMOVED***: inputVal }),
    ***REMOVED***);
      const data = await resp.json();

      if (data.success) {
        const parsed = JSON.parse(data.result);
        addLog("info", data.result);

        // Update threat level based on results
        if (parsed.verdict === "MALICIOUS" || parsed.verdict === "HIGH RISK") {
          setThreatLevel("HIGH");
          addLog("error", `{"event":"THREAT_ESCALATION","level":"HIGH","source":"${config.tool}"}`);
      ***REMOVED***

        // Add result to chat as AI message
        setMessages((prev) => ***REMOVED***
          ...prev,
        ***REMOVED*** role: "ai", content: formatToolResult(config.tool, parsed) },
        ***REMOVED***);
    ***REMOVED*** else {
        addLog("error", `{"event":"TOOL_ERROR","tool":"${config.tool}","error":"${data.result}"}`);
        setMessages((prev) => ***REMOVED***
          ...prev,
        ***REMOVED*** role: "ai", content: `❌ **Tool Error:** ${data.result}` },
        ***REMOVED***);
    ***REMOVED***
  ***REMOVED*** catch (e) {
      debugLog("H2", "app/page.tsx:runTool:error", "Tool invocation failed", {
        tool: config.tool,
        endpoint: `${API_BASE}${config.endpoint}`,
        error: e instanceof Error ? e.message : String(e),
        online: typeof navigator !== "undefined" ? navigator.onLine : null,
    ***REMOVED***);
      addLog("error", `{"event":"TOOL_ERROR","tool":"${config.tool}","error":"Network error"}`);
      setMessages((prev) => ***REMOVED***
        ...prev,
      ***REMOVED*** role: "ai", content: "❌ **Connection Error:** Could not reach the backend API. Make sure the FastAPI server is running on port 8000." },
      ***REMOVED***);
  ***REMOVED***
    setToolLoading(false);
***REMOVED***;

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
  ***REMOVED***
***REMOVED***

  // ─── Chat Send ────────────────────────────
  const handleSend = async () => {
    if (!inputValue.trim() || chatLoading) return;
    const userMsg = inputValue.trim();
    setInputValue("");
    setMessages((prev) => ***REMOVED***...prev, { role: "user", content: userMsg }***REMOVED***);
    setChatLoading(true);
    debugLog("H3", "app/page.tsx:chat:start", "Chat request started", {
      endpoint: `${API_BASE}/api/chat`,
      promptLength: userMsg.length,
  ***REMOVED***);
    addLog("info", `{"event":"AGENT_QUERY","prompt":"${userMsg.slice(0, 60)}"}`);

    try {
      const resp = await fetch(`${API_BASE}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: userMsg }),
    ***REMOVED***);
      const data = await resp.json();
      addLog("info", '{"event":"AGENT_RESPONSE","status":"complete"}');
      setMessages((prev) => ***REMOVED***
        ...prev,
      ***REMOVED*** role: "ai", content: data.success ? data.response : `❌ **Error:** ${data.response}` },
      ***REMOVED***);
  ***REMOVED*** catch (err: unknown) {
      debugLog("H3", "app/page.tsx:chat:error", "Chat request failed", {
        endpoint: `${API_BASE}/api/chat`,
        error: err instanceof Error ? err.message : String(err),
        online: typeof navigator !== "undefined" ? navigator.onLine : null,
    ***REMOVED***);
      addLog("error", '{"event":"AGENT_ERROR","msg":"Backend unreachable"}');
      setMessages((prev) => ***REMOVED***
        ...prev,
      ***REMOVED*** role: "ai", content: "❌ **Connection Error:** Could not reach the backend API. Make sure the FastAPI server is running on port 8000." },
      ***REMOVED***);
  ***REMOVED***
    setChatLoading(false);
***REMOVED***;

  const pad = (n: number) => n.toString().padStart(2, "0");

  const METRICS = ***REMOVED***
  ***REMOVED***
      label: "SYSTEM STATUS",
      value: apiStatus === "online" ? "ONLINE" : apiStatus === "offline" ? "OFFLINE" : "...",
      delta: apiStatus === "online" ? "All Systems Nominal" : apiStatus === "offline" ? "API Unreachable" : "Checking...",
      icon: ShieldCheck,
      accent: apiStatus === "offline" ? "accent-left-red" : "accent-left-green",
      shadow: apiStatus === "offline" ? "float-shadow-red" : "float-shadow-green",
      valueColor: apiStatus === "offline" ? "text-red" : "text-green",
      deltaColor: apiStatus === "offline" ? "text-red-dim" : "text-green-dim",
  ***REMOVED***,
  ***REMOVED***
      label: "ACTIVE SENSORS",
      value: sensorCount.toString(),
      delta: "IoT Endpoints",
      icon: Wifi,
      accent: "accent-left-cyan",
      shadow: "float-shadow-cyan",
      valueColor: "text-cyan",
      deltaColor: "text-cyan-dim",
  ***REMOVED***,
  ***REMOVED***
      label: "THREAT LEVEL",
      value: threatLevel,
      delta: threatLevel === "HIGH" ? "Active Alerts" : threatLevel === "MONITORING" ? "Scanning" : "Clear",
      icon: AlertTriangle,
      accent: threatLevel === "HIGH" ? "accent-left-red" : "accent-left-amber",
      shadow: threatLevel === "HIGH" ? "float-shadow-red" : "float-shadow-cyan",
      valueColor: threatLevel === "HIGH" ? "text-red" : "text-amber",
      deltaColor: threatLevel === "HIGH" ? "text-red-dim" : "text-amber",
  ***REMOVED***,
  ***REMOVED***
      label: "UPTIME",
      value: `${pad(uptime.h)}:${pad(uptime.m)}:${pad(uptime.s)}`,
      delta: "Session Active",
      icon: Clock,
      accent: "accent-left-amber",
      shadow: "float-shadow-cyan",
      valueColor: "text-cyan",
      deltaColor: "text-amber",
  ***REMOVED***,
  ***REMOVED***;

  const TOOLS = ***REMOVED***
  ***REMOVED*** key: "scanner", label: "Network Scanner", icon: Radar, desc: "Autoencoder Scan" },
  ***REMOVED*** key: "ip", label: "IP Check", icon: Globe, desc: "VirusTotal Intel" },
  ***REMOVED*** key: "mac", label: "MAC Lookup", icon: Fingerprint, desc: "Device Vendor ID" },
  ***REMOVED*** key: "cve", label: "CVE Database", icon: Bug, desc: "NIST NVD Query" },
  ***REMOVED***;

  return (
    <div className="min-h-screen px-4 py-3 md:px-6 lg:px-8 max-w-***REMOVED***1440px***REMOVED*** mx-auto flex flex-col gap-4">
    ***REMOVED***/* ═══════════ SOC STATUS BANNER (Sandbox Mode) ═══════════ */}
    ***REMOVED***apiStatus === "online" && (
        <div className="glass-strong border-amber/30 bg-amber/5 px-4 py-2 flex flex-col sm:flex-row items-center justify-between gap-3 animate-fade-in-up">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-amber/20 border border-amber/40">
              <Zap className="w-4 h-4 text-amber animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-display text-***REMOVED***0.65rem***REMOVED*** font-bold tracking-***REMOVED***2px***REMOVED*** text-amber uppercase">SOC Sandbox Mode Active</span>
                <span className="h-1 w-1 rounded-full bg-amber/60" />
                <span className="text-***REMOVED***0.6rem***REMOVED*** text-amber/80 font-medium uppercase tracking-wider">Operational Limited</span>
              </div>
              <p className="text-***REMOVED***0.55rem***REMOVED*** text-text-muted uppercase tracking-widest mt-0.5">
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
            <span className="text-***REMOVED***0.6rem***REMOVED*** font-bold text-amber tracking-widest uppercase">Configure API</span>
          </button>
        </div>
      )}

    ***REMOVED***/* ═══════════ TOOL INPUT MODAL ═══════════ */}
    ***REMOVED***activeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="glass-strong float-shadow-cyan p-6 w-full max-w-md mx-4 animate-fade-in-up">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-display text-xs font-semibold tracking-***REMOVED***2px***REMOVED*** text-cyan uppercase">
              ***REMOVED***activeModal.label}
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
            ***REMOVED***}
              placeholder={activeModal.placeholder}
              className="input-glow w-full px-4 py-2.5 text-***REMOVED***0.82rem***REMOVED*** mb-4"
            />
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setActiveModal(null)}
                className="px-4 py-2 text-***REMOVED***0.72rem***REMOVED*** text-text-muted hover:text-text transition-colors"
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

    ***REMOVED***/* ═══════════ HEADER ═══════════ */}
      <header className="glass-strong float-shadow-cyan px-5 py-4 md:px-8 md:py-5 flex items-center justify-between relative overflow-hidden animate-fade-in-up">
        <div className="absolute top-0 left-0 right-0 h-***REMOVED***2px***REMOVED*** bg-gradient-to-r from-transparent via-cyan to-transparent opacity-60" />
        <div className="flex items-center gap-4">
          <div className="w-11 h-11 md:w-14 md:h-14 rounded-xl bg-cyan-muted border border-border-active flex items-center justify-center flex-shrink-0 overflow-hidden">
            <img src="/logo.png" alt="CYBERSICKER Logo" className="w-full h-full object-cover" />
          </div>
          <div>
            <h1 className="font-display text-xl md:text-2xl lg:text-3xl font-bold tracking-***REMOVED***3px***REMOVED*** text-cyan drop-shadow-***REMOVED***0_0_20px_rgba(0,240,255,0.3)***REMOVED***">
              CYBERSICKER
            </h1>
            <p className="text-***REMOVED***0.6rem***REMOVED*** md:text-***REMOVED***0.7rem***REMOVED*** text-text-muted tracking-***REMOVED***2px***REMOVED*** uppercase mt-0.5">
              Autonomous IoT Blue Team Agent — Threat Detection & Response
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="hidden md:flex items-center gap-2 text-***REMOVED***0.65rem***REMOVED*** text-text-muted tracking-wider">
            <Activity className="w-3.5 h-3.5 text-green animate-glow" />
            <span>LIVE</span>
          </div>
          <div className="animate-pulse-badge bg-red text-white text-***REMOVED***0.6rem***REMOVED*** md:text-***REMOVED***0.65rem***REMOVED*** font-semibold px-3 py-1.5 md:px-4 md:py-1.5 rounded-full tracking-***REMOVED***2px***REMOVED*** uppercase font-display flex items-center gap-2">
            <Zap className="w-3 h-3" />
            SOC ACTIVE
          </div>
        </div>
        <div className="absolute top-0 left-***REMOVED***-100%***REMOVED*** w-full h-full bg-gradient-to-r from-transparent via-cyan/***REMOVED***0.03***REMOVED*** to-transparent animate-scanline pointer-events-none" />
      </header>

    ***REMOVED***/* ═══════════ METRIC CARDS ═══════════ */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 md:gap-4">
      ***REMOVED***METRICS.map((m, i) => (
          <div key={m.label} className={`glass-card ${m.accent} ${m.shadow} px-4 py-4 md:px-5 md:py-5 animate-fade-in-up`} style={{ animationDelay: `${i * 80}ms` }}>
            <div className="flex items-start justify-between mb-3">
              <span className="text-***REMOVED***0.6rem***REMOVED*** text-text-muted tracking-***REMOVED***1.5px***REMOVED*** uppercase font-medium">{m.label}</span>
              <m.icon className={`w-4 h-4 ${m.valueColor} opacity-60`} />
            </div>
            <div className={`font-display text-xl md:text-2xl font-bold ${m.valueColor} tracking-wider`}>{m.value}</div>
            <div className={`text-***REMOVED***0.6rem***REMOVED*** ${m.deltaColor} mt-1.5 flex items-center gap-1`}>
              <ChevronRight className="w-3 h-3" />
            ***REMOVED***m.delta}
            </div>
          </div>
        ))}
      </div>

    ***REMOVED***/* ═══════════ MAIN CONTENT ═══════════ */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 md:gap-5 flex-1 min-h-0">
      ***REMOVED***/* ── LEFT COLUMN ── */}
        <div className="lg:col-span-4 flex flex-col gap-4">
        ***REMOVED***/* Tool Buttons */}
          <div className="glass-strong float-shadow-cyan p-4 md:p-5 animate-fade-in-up" style={{ animationDelay: "250ms" }}>
            <div className="flex items-center gap-2 mb-4">
              <Terminal className="w-4 h-4 text-cyan opacity-70" />
              <h2 className="font-display text-***REMOVED***0.7rem***REMOVED*** md:text-xs font-semibold tracking-***REMOVED***2px***REMOVED*** text-cyan uppercase">Agent Tools</h2>
            ***REMOVED***toolLoading && <Loader2 className="w-3.5 h-3.5 text-cyan animate-spin ml-auto" />}
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-1 gap-2">
            ***REMOVED***TOOLS.map((tool) => (
                <button
                  key={tool.key}
                  disabled={toolLoading}
                  suppressHydrationWarning
                  onClick={() => {
                    const config = TOOL_CONFIGS***REMOVED***tool.key***REMOVED***;
                    if (config) {
                      setModalInput(config.placeholder);
                      setActiveModal(config);
                  ***REMOVED***
                ***REMOVED***}
                  className="btn-tool group disabled:opacity-40 disabled:cursor-wait"
                >
                  <tool.icon className="w-4 h-4 flex-shrink-0 opacity-70 group-hover:opacity-100 transition-opacity" />
                  <div className="text-left">
                    <div>{tool.label}</div>
                    <div className="text-***REMOVED***0.58rem***REMOVED*** text-text-muted mt-0.5 group-hover:text-cyan-dim transition-colors">{tool.desc}</div>
                  </div>
                </button>
              ))}
            </div>
          </div>

        ***REMOVED***/* Terminal Log */}
          <div className="glass-strong float-shadow-cyan p-4 md:p-5 flex-1 flex flex-col min-h-***REMOVED***280px***REMOVED*** animate-fade-in-up" style={{ animationDelay: "350ms" }}>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className="flex gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-red/60" />
                  <span className="w-2.5 h-2.5 rounded-full bg-amber/60" />
                  <span className="w-2.5 h-2.5 rounded-full bg-green/60" />
                </div>
                <h2 className="font-display text-***REMOVED***0.65rem***REMOVED*** md:text-***REMOVED***0.7rem***REMOVED*** font-semibold tracking-***REMOVED***2px***REMOVED*** text-cyan uppercase">System Logs</h2>
              </div>
              <span className="text-***REMOVED***0.55rem***REMOVED*** text-text-muted tracking-wider">LIVE FEED</span>
            </div>
            <div ref={terminalRef} className="flex-1 overflow-y-auto bg-black/30 rounded-lg p-3 terminal-log">
            ***REMOVED***logs.map((log, i) => (
                <div key={i} className="flex gap-2 py-0.5">
                  <span className="log-timestamp shrink-0">***REMOVED***{log.ts}***REMOVED***</span>
                  <span className={`shrink-0 ${log.level === "error" ? "log-error" : log.level === "warn" ? "log-warn" : "log-info"}`}>
                  ***REMOVED***log.level === "error" ? "ERR" : log.level === "warn" ? "WRN" : "INF"}
                  </span>
                  <span className="opacity-70 break-all">{log.msg}</span>
                </div>
              ))}
              <div className="flex items-center gap-1 mt-1 text-cyan-dim animate-glow"><span>█</span></div>
            </div>
          </div>
        </div>

      ***REMOVED***/* ── RIGHT COLUMN: AI Agent Chat ── */}
        <div className="lg:col-span-8 glass-strong float-shadow-cyan flex flex-col min-h-***REMOVED***500px***REMOVED*** lg:min-h-0 animate-fade-in-up" style={{ animationDelay: "200ms" }}>
        ***REMOVED***/* Chat Header */}
          <div className="px-5 py-4 border-b border-border flex items-center justify-between shrink-0">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-cyan-muted border border-border-active flex items-center justify-center">
                <Shield className="w-4 h-4 text-cyan" />
              </div>
              <div>
                <h2 className="font-display text-***REMOVED***0.7rem***REMOVED*** md:text-xs font-semibold tracking-***REMOVED***2px***REMOVED*** text-cyan uppercase">Cybersicker Agent</h2>
                <p className="text-***REMOVED***0.55rem***REMOVED*** text-green flex items-center gap-1 mt-0.5">
                  <span className={`w-1.5 h-1.5 rounded-full ${apiStatus === "online" ? "bg-green animate-glow" : "bg-red"} inline-block`} />
                ***REMOVED***apiStatus === "online" ? "Online — Gemini 2.5 Flash" : "Offline — Backend Unreachable"}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 text-***REMOVED***0.6rem***REMOVED*** text-text-muted">
              <Activity className="w-3 h-3" />
              <span className="hidden sm:inline">Threat Intel Protocol Active</span>
            </div>
          </div>

        ***REMOVED***/* Chat Messages */}
          <div className="flex-1 overflow-y-auto px-4 py-4 md:px-5 space-y-3">
            <div className="text-center py-2">
              <span className="text-***REMOVED***0.58rem***REMOVED*** text-text-muted bg-bg-card-solid px-3 py-1 rounded-full tracking-wider">
                SESSION INITIATED — CYBERSICKER SOC v2.0
              </span>
            </div>

          ***REMOVED***messages.length === 0 && (
              <div className="text-center py-12">
                <Shield className="w-12 h-12 text-cyan/20 mx-auto mb-3" />
                <p className="text-***REMOVED***0.75rem***REMOVED*** text-text-muted">Use the Agent Tools or type a command below to begin.</p>
                <p className="text-***REMOVED***0.6rem***REMOVED*** text-text-muted/60 mt-1">Try: &quot;Scan KDDTrain+.txt&quot; or &quot;Check IP 185.220.101.43&quot;</p>
              </div>
            )}

          ***REMOVED***messages.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                <div className={`max-w-***REMOVED***85%***REMOVED*** md:max-w-***REMOVED***75%***REMOVED*** px-4 py-3 ${msg.role === "user" ? "chat-bubble-user" : "chat-bubble-ai"}`}>
                  <div className={`text-***REMOVED***0.55rem***REMOVED*** font-semibold tracking-***REMOVED***1.5px***REMOVED*** uppercase mb-1.5 ${msg.role === "user" ? "text-cyan-dim" : "text-green-dim"}`}>
                  ***REMOVED***msg.role === "user" ? "👤 OPERATOR" : "🛡️ CYBERSICKER"}
                  </div>
                  <div className="text-***REMOVED***0.78rem***REMOVED*** md:text-***REMOVED***0.82rem***REMOVED*** leading-relaxed text-text whitespace-pre-wrap">
                  ***REMOVED***msg.content.split(/(\*\*.*?\*\*|`.*?`)/g).map((part, j) => {
                      if (part.startsWith("**") && part.endsWith("**"))
                        return <strong key={j} className="text-cyan font-semibold">{part.slice(2, -2)}</strong>;
                      if (part.startsWith("`") && part.endsWith("`"))
                        return <code key={j} className="bg-black/40 text-green px-1.5 py-0.5 rounded text-***REMOVED***0.72rem***REMOVED***">{part.slice(1, -1)}</code>;
                      return <span key={j}>{part}</span>;
                  ***REMOVED***)}
                  </div>
                </div>
              </div>
            ))}

          ***REMOVED***chatLoading && (
              <div className="flex justify-start">
                <div className="chat-bubble-ai px-4 py-3 flex items-center gap-2">
                  <Loader2 className="w-4 h-4 text-cyan animate-spin" />
                  <span className="text-***REMOVED***0.75rem***REMOVED*** text-text-muted">Cybersicker is analyzing...</span>
                </div>
              </div>
            )}

            <div ref={chatEndRef} />
          </div>

        ***REMOVED***/* Chat Input */}
          <div className="px-4 py-3 md:px-5 md:py-4 border-t border-border shrink-0">
            <div className="flex gap-2 md:gap-3">
              <input
                type="text"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSend()}
                placeholder="Enter a command for Cybersicker..."
                className="input-glow flex-1 px-4 py-2.5 text-***REMOVED***0.8rem***REMOVED***"
                disabled={chatLoading}
                suppressHydrationWarning
              />
              <button onClick={handleSend} disabled={chatLoading} className="btn-send flex items-center gap-2 disabled:opacity-40" suppressHydrationWarning>
              ***REMOVED***chatLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                <span className="hidden sm:inline">Send</span>
              </button>
            </div>
          </div>
        </div>
      </div>

    ***REMOVED***/* ═══════════ FOOTER ═══════════ */}
      <footer className="text-center py-4 animate-fade-in-up" style={{ animationDelay: "500ms" }}>
        <div className="text-***REMOVED***0.58rem***REMOVED*** text-text-muted tracking-***REMOVED***2px***REMOVED*** uppercase">
          Powered by{" "}
          <span className="text-cyan-dim font-medium">Vrishin Ram K</span>
        </div>
      </footer>
    </div>
  );
}
