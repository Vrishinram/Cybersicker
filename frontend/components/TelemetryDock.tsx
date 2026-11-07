"use client";

import React, { useEffect, useRef, useMemo } from "react";

export type LogLevel = "info" | "warn" | "error";

export interface LogEntry {
  ts: string;
  level: LogLevel;
  msg: string;
}

interface TelemetryDockProps {
  logs: LogEntry[];
  filter: "ALL" | LogLevel;
  onFilterChange: (filter: "ALL" | LogLevel) => void;
}

export default function TelemetryDock({
  logs,
  filter,
  onFilterChange,
}: TelemetryDockProps) {
  const terminalRef = useRef<HTMLDivElement>(null);

  // Instant filter computation
  const filteredLogs = useMemo(() => {
    if (filter === "ALL") return logs;
    return logs.filter((log) => log.level === filter);
  }, [logs, filter]);

  // Auto-scroll to latest log line as events stream in
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [filteredLogs]);

  // Helper to highlight JSON payload syntax
  const renderLogMessage = (msg: string) => {
    const trimmed = msg.trim();
    let parsed: Record<string, any> | null = null;

    if (
      (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
      (trimmed.startsWith("[") && trimmed.endsWith("]"))
    ) {
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        parsed = null;
      }
    }

    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const keys = Object.keys(parsed);
      return (
        <span className="font-mono inline-flex flex-wrap gap-x-1 items-baseline">
          <span className="text-[var(--text-muted)]">&#123;</span>
          {keys.map((key, idx) => {
            const val = parsed![key];
            const valStr = typeof val === "object" ? JSON.stringify(val) : String(val);
            const upper = valStr.toUpperCase();

            let valClass = "text-[var(--text-medium)]";
            if (
              upper.includes("MALICIOUS") ||
              upper.includes("CRITICAL") ||
              upper.includes("ERROR") ||
              upper.includes("FAILED") ||
              upper.includes("HIGH") ||
              upper.includes("BLOCKED")
            ) {
              valClass = "text-[#ff5252] font-semibold";
            } else if (
              upper.includes("SUSPICIOUS") ||
              upper.includes("WARN") ||
              upper.includes("ANOMALY") ||
              upper.includes("OUTLIER")
            ) {
              valClass = "text-[#ffb300] font-semibold";
            } else if (
              upper.includes("CLEAN") ||
              upper.includes("READY") ||
              upper.includes("OK") ||
              upper.includes("SUCCESS") ||
              upper.includes("ONLINE") ||
              upper.includes("COMPLETE") ||
              upper.includes("DONE") ||
              upper.includes("BENIGN")
            ) {
              valClass = "text-[#00ff9d] font-semibold";
            } else if (typeof val === "number") {
              valClass = "text-purple-300";
            } else if (typeof val === "boolean") {
              valClass = val ? "text-[#00ff9d]" : "text-[#ff5252]";
            }

            return (
              <span key={key} className="inline-flex items-center">
                <span className="text-cyan-400 font-semibold">&quot;{key}&quot;</span>
                <span className="text-[var(--text-muted)] mr-1">:</span>
                <span className={valClass}>
                  {typeof val === "string" ? `"${val}"` : valStr}
                </span>
                {idx < keys.length - 1 && (
                  <span className="text-[var(--text-muted)] mr-1">,</span>
                )}
              </span>
            );
          })}
          <span className="text-[var(--text-muted)]">&#125;</span>
        </span>
      );
    }

    return <span>{msg}</span>;
  };

  return (
    <div className="surface-panel p-4 flex-1 flex flex-col min-h-[300px]">
      <div className="flex items-center justify-between pb-2 mb-2 border-b border-[var(--border-subtle)]">
        <span className="font-heading font-semibold text-xs text-[var(--text-high)] uppercase tracking-wide">
          System Telemetry Log
        </span>
        <div className="flex gap-1 font-mono text-[0.62rem]">
          {(["ALL", "info", "warn", "error"] as const).map((lvl) => (
            <button
              key={lvl}
              onClick={() => onFilterChange(lvl)}
              className={`px-1.5 py-0.5 rounded uppercase cursor-pointer transition-all active:scale-90 ${
                filter === lvl
                  ? "bg-[var(--accent-primary)] text-white font-semibold shadow-[0_0_8px_rgba(56,189,248,0.4)]"
                  : "bg-[var(--surface-elevated)] text-[var(--text-muted)] hover:text-white hover:bg-[var(--surface-elevated)]/90"
              }`}
            >
              {lvl === "info" ? "INF" : lvl === "warn" ? "WRN" : lvl === "error" ? "ERR" : "ALL"}
            </button>
          ))}
        </div>
      </div>

      <div
        ref={terminalRef}
        className="flex-1 overflow-y-auto log-stream p-2.5 space-y-1 font-mono text-[0.68rem]"
      >
        {filteredLogs.length === 0 ? (
          <div className="text-[var(--text-muted)] text-[0.65rem] italic py-2">
            No telemetry records match current level filter.
          </div>
        ) : (
          filteredLogs.map((log, i) => (
            <div key={i} className="flex gap-2 log-entry-item leading-snug animate-log-slide">
              <span className="text-[var(--text-muted)] shrink-0 select-none">{log.ts}</span>
              <span
                className={`shrink-0 font-bold select-none ${
                  log.level === "error"
                    ? "text-[var(--status-danger)]"
                    : log.level === "warn"
                    ? "text-[var(--status-warning)]"
                    : "text-[var(--accent-light)]"
                }`}
              >
                {log.level === "error" ? "ERR" : log.level === "warn" ? "WRN" : "INF"}
              </span>
              <div className="text-[var(--text-medium)] break-all flex-1">
                {renderLogMessage(log.msg)}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

