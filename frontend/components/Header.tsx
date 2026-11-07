"use client";

import React from "react";
import { CheckCircle2, Clock, RotateCcw } from "lucide-react";

interface HeaderProps {
  apiStatus: "online" | "offline" | "checking";
  uptime: { h: number; m: number; s: number };
  onResetSession: () => void;
  modelName?: string;
}

export default function Header({
  apiStatus,
  uptime,
  onResetSession,
  modelName = "OLLAMA (LLAMA3.2)",
}: HeaderProps) {
  const pad = (n: number) => n.toString().padStart(2, "0");

  const handleReset = () => {
    const confirmed = window.confirm(
      "Confirm session reset? All chat history and active indicator tracking will be flushed to clean state."
    );
    if (confirmed) {
      onResetSession();
    }
  };

  return (
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
            Open-source blue-team workbench: Deep neural autoencoder anomaly scoring &amp; automated threat enrichment.
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3 md:gap-4">
        {/* Status Badges */}
        <div className="hidden md:flex items-center gap-3 font-mono text-[0.7rem] border-r border-[var(--border-subtle)] pr-4">
          <div className="flex items-center gap-1.5">
            <span
              className={`w-2 h-2 rounded-full ${
                apiStatus === "online"
                  ? "bg-[var(--status-success-bd)] animate-pulse-live"
                  : "bg-[var(--status-danger-bd)]"
              }`}
            />
            <span className="text-[var(--text-muted)]">API :8000</span>
          </div>
          <div className="flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-[var(--accent-light)]" />
            <span className="text-[var(--text-muted)] uppercase tracking-wider">{modelName}</span>
          </div>
        </div>

        {/* Uptime Timer */}
        <div className="flex items-center gap-2 font-mono text-[0.68rem]">
          <Clock className="w-3.5 h-3.5 text-[var(--text-muted)]" />
          <span className="text-[var(--text-high)] font-semibold">
            {pad(uptime.h)}:{pad(uptime.m)}:{pad(uptime.s)}
          </span>
        </div>

        {/* Requirement 3: [RESET SESSION] Control next to uptime timer */}
        <button
          onClick={handleReset}
          title="Reset session history and telemetry logs to boot state"
          className="font-mono text-[0.68rem] px-2.5 py-1.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] text-[var(--text-medium)] hover:text-[var(--status-danger)] hover:border-[var(--status-danger-bd)] hover:bg-[var(--status-danger-bg)]/20 transition-all flex items-center gap-1.5 cursor-pointer uppercase tracking-wider font-semibold"
        >
          <RotateCcw className="w-3 h-3 text-[var(--accent-light)] group-hover:text-[var(--status-danger)]" />
          <span>RESET SESSION</span>
        </button>
      </div>
    </header>
  );
}

