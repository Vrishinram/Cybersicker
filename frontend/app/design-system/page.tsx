"use client";

import { useMemo, useState } from "react";
import { AlertModal } from "@/components/cyber/alert-modal";
import { LogPanel } from "@/components/cyber/log-panel";
import { ScanButton } from "@/components/cyber/scan-button";

const SAMPLE_LOGS = [
  { timestamp: "11:27:18", level: "info" as const, message: "Agent Kestrel mapped subnet 10.20.18.0/24." },
  { timestamp: "11:27:20", level: "warn" as const, message: "Anomaly score 0.72 on host NODE-14." },
  { timestamp: "11:27:23", level: "critical" as const, message: "Credential exfil pattern on SRV-12 detected." }
];

export default function DesignSystemPage() {
  const [scanActive, setScanActive] = useState(true);
  const [alertOpen, setAlertOpen] = useState(false);

  const statusLabel = useMemo(() => (scanActive ? "Agent swarm hunting threats" : "Agent swarm paused"), [scanActive]);

  return (
    <main className="min-h-screen bg-[#06080d] bg-cyber-grid px-4 py-8 text-slate-100 md:px-8">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
        <header className="cyber-panel px-5 py-5 md:px-7">
          <p className="font-mono text-xs uppercase tracking-[0.2em] text-cyan-200">Cybersicker UI Foundation</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-50">Premium cyberpunk design starter</h1>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300">
            This route demonstrates reusable Tailwind patterns for agent activity controls, real-time scanning logs, and critical alert overlays.
          </p>
          <div className="mt-5 flex flex-wrap items-center gap-3">
            <ScanButton active={scanActive} onClick={() => setScanActive((current) => !current)}>
            {scanActive ? "Pause Scan" : "Resume Scan"}
            </ScanButton>
            <ScanButton onClick={() => setAlertOpen(true)}>Trigger Alert Modal</ScanButton>
            <span className="rounded-full border border-cyan-300/25 bg-cyan-500/10 px-3 py-1 font-mono text-xs text-cyan-100">
            {statusLabel}
            </span>
          </div>
        </header>

        <section className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          <LogPanel title="Active Scanning Stream" logs={SAMPLE_LOGS} />
          <div className="cyber-panel p-5">
            <p className="font-mono text-xs uppercase tracking-[0.2em] text-cyan-200">Palette tokens</p>
            <div className="mt-4 grid grid-cols-2 gap-3 text-xs md:grid-cols-3">
            {[
                ["Base 0", "#06080D", "bg-[#06080D]"],
                ["Base 1", "#0B1020", "bg-[#0B1020]"],
                ["Accent Green", "#00FF9D", "bg-[#00FF9D]"],
                ["Accent Cyan", "#00D1FF", "bg-[#00D1FF]"],
                ["Danger", "#FF3B5C", "bg-[#FF3B5C]"],
                ["Warning", "#FFB020", "bg-[#FFB020]"],
              ].map(([name, value, bgClass]) => (
                <div key={name} className="rounded-lg border border-slate-700 p-2">
                  <div className={`h-8 rounded ${bgClass}`} />
                  <p className="mt-2 text-slate-200">{name}</p>
                  <p className="font-mono text-slate-400">{value}</p>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>

      <AlertModal
        open={alertOpen}
        onClose={() => setAlertOpen(false)}
        title="Possible credential exfiltration"
        description="Agent Kestrel correlated suspicious process behavior with outbound transfer attempts from SRV-12. Immediate isolation is recommended."
      />
    </main>
  );
}
