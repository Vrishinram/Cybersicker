"use client";

import { useMemo, useState } from "react";
import { AlertModal } from "@/components/cyber/alert-modal";
import { LogPanel } from "@/components/cyber/log-panel";
import { ScanButton } from "@/components/cyber/scan-button";

const SAMPLE_LOGS = ***REMOVED***
***REMOVED*** timestamp: "11:27:18", level: "info" as const, message: "Agent Kestrel mapped subnet 10.20.18.0/24." },
***REMOVED*** timestamp: "11:27:20", level: "warn" as const, message: "Anomaly score 0.72 on host NODE-14." },
***REMOVED*** timestamp: "11:27:23", level: "critical" as const, message: "Credential exfil pattern on SRV-12 detected." },
***REMOVED***;

export default function DesignSystemPage() {
  const ***REMOVED***scanActive, setScanActive***REMOVED*** = useState(true);
  const ***REMOVED***alertOpen, setAlertOpen***REMOVED*** = useState(false);

  const statusLabel = useMemo(() => (scanActive ? "Agent swarm hunting threats" : "Agent swarm paused"), ***REMOVED***scanActive***REMOVED***);

  return (
    <main className="min-h-screen bg-***REMOVED***#06080d***REMOVED*** bg-cyber-grid px-4 py-8 text-slate-100 md:px-8">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
        <header className="cyber-panel px-5 py-5 md:px-7">
          <p className="font-mono text-xs uppercase tracking-***REMOVED***0.2em***REMOVED*** text-cyan-200">Cybersicker UI Foundation</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-50">Premium cyberpunk design starter</h1>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300">
            This route demonstrates reusable Tailwind patterns for agent activity controls, real-time scanning logs, and critical alert overlays.
          </p>
          <div className="mt-5 flex flex-wrap items-center gap-3">
            <ScanButton active={scanActive} onClick={() => setScanActive((current) => !current)}>
            ***REMOVED***scanActive ? "Pause Scan" : "Resume Scan"}
            </ScanButton>
            <ScanButton onClick={() => setAlertOpen(true)}>Trigger Alert Modal</ScanButton>
            <span className="rounded-full border border-cyan-300/25 bg-cyan-500/10 px-3 py-1 font-mono text-xs text-cyan-100">
            ***REMOVED***statusLabel}
            </span>
          </div>
        </header>

        <section className="grid gap-6 lg:grid-cols-***REMOVED***1.1fr_0.9fr***REMOVED***">
          <LogPanel title="Active Scanning Stream" logs={SAMPLE_LOGS} />
          <div className="cyber-panel p-5">
            <p className="font-mono text-xs uppercase tracking-***REMOVED***0.2em***REMOVED*** text-cyan-200">Palette tokens</p>
            <div className="mt-4 grid grid-cols-2 gap-3 text-xs md:grid-cols-3">
            ***REMOVED******REMOVED***
                ***REMOVED***"Base 0", "#06080D", "bg-***REMOVED***#06080D***REMOVED***"***REMOVED***,
                ***REMOVED***"Base 1", "#0B1020", "bg-***REMOVED***#0B1020***REMOVED***"***REMOVED***,
                ***REMOVED***"Accent Green", "#00FF9D", "bg-***REMOVED***#00FF9D***REMOVED***"***REMOVED***,
                ***REMOVED***"Accent Cyan", "#00D1FF", "bg-***REMOVED***#00D1FF***REMOVED***"***REMOVED***,
                ***REMOVED***"Danger", "#FF3B5C", "bg-***REMOVED***#FF3B5C***REMOVED***"***REMOVED***,
                ***REMOVED***"Warning", "#FFB020", "bg-***REMOVED***#FFB020***REMOVED***"***REMOVED***,
              ***REMOVED***.map((***REMOVED***name, value, bgClass***REMOVED***) => (
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
