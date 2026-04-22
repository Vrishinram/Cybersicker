type AlertModalProps = {
  open: boolean;
  title: string;
  description: string;
  onClose: () => void;
};

export function AlertModal({ open, title, description, onClose }: AlertModalProps) {
  if (!open) {
    return null;
***REMOVED***

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-2xl border border-rose-300/45 bg-slate-950/90 p-6 shadow-***REMOVED***0_0_45px_rgba(255,59,92,0.24)***REMOVED***">
        <p className="font-mono text-xs uppercase tracking-***REMOVED***0.2em***REMOVED*** text-rose-300">Critical Alert</p>
        <h2 className="mt-2 text-xl font-semibold text-slate-100">{title}</h2>
        <p className="mt-3 text-sm leading-6 text-slate-300">{description}</p>
        <div className="mt-6 flex gap-3">
          <button
            type="button"
            className="cyber-focus-ring rounded-lg border border-rose-300/45 bg-rose-500/15 px-4 py-2 text-sm font-medium text-rose-200 transition hover:bg-rose-500/25"
          >
            Isolate Host
          </button>
          <button
            type="button"
            onClick={onClose}
            className="cyber-focus-ring rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-300 transition hover:bg-slate-800"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}
