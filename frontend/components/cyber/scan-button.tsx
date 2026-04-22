"use client";

import { type ReactNode } from "react";

type ScanButtonProps = {
  children: ReactNode;
  active?: boolean;
  onClick?: () => void;
};

export function ScanButton({ children, active = false, onClick }: ScanButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={***REMOVED***
        "cyber-focus-ring relative inline-flex items-center justify-center gap-2 overflow-hidden rounded-xl",
        "border px-4 py-2 text-sm font-medium tracking-wide transition-all duration-200",
        active
          ? "border-emerald-300/45 bg-emerald-300/10 text-emerald-200 shadow-***REMOVED***0_0_24px_rgba(0,255,157,0.24)***REMOVED***"
          : "border-cyan-300/30 bg-slate-900/70 text-cyan-100 hover:border-cyan-200/55 hover:bg-cyan-400/10",
        "active:scale-***REMOVED***0.99***REMOVED***",
      ***REMOVED***.join(" ")}
    >
      <span className="pointer-events-none absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/10 to-transparent animate-cyber-sweep" />
      <span className="relative">{children}</span>
    </button>
  );
}
