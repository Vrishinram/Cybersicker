type LogEntry = {
  timestamp: string;
  level: "info" | "warn" | "critical";
  message: string;
};

type LogPanelProps = {
  title: string;
  logs: LogEntry***REMOVED******REMOVED***;
};

const toneByLevel: Record<LogEntry***REMOVED***"level"***REMOVED***, string> = {
  info: "text-emerald-300",
  warn: "text-amber-300",
  critical: "text-rose-300",
};

export function LogPanel({ title, logs }: LogPanelProps) {
  return (
    <section className="cyber-panel overflow-hidden">
      <header className="flex items-center justify-between border-b border-cyan-300/15 px-4 py-3">
        <h3 className="font-mono text-xs uppercase tracking-***REMOVED***0.2em***REMOVED*** text-cyan-100">{title}</h3>
        <span className="inline-flex items-center gap-2 rounded-full border border-emerald-300/35 bg-emerald-300/10 px-2 py-1 font-mono text-***REMOVED***10px***REMOVED*** text-emerald-200">
          <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-300" />
          scanning
        </span>
      </header>
      <div className="max-h-72 overflow-auto bg-black/35 p-4 font-mono text-xs tabular-nums">
      ***REMOVED***logs.map((entry) => (
          <div key={`${entry.timestamp}-${entry.message}`} className="mb-2 grid grid-cols-***REMOVED***82px_60px_1fr***REMOVED*** gap-2">
            <span className="text-cyan-300/70">***REMOVED***{entry.timestamp}***REMOVED***</span>
            <span className={toneByLevel***REMOVED***entry.level***REMOVED***}>{entry.level.toUpperCase()}</span>
            <span className="text-slate-300">{entry.message}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
