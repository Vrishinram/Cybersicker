"use client";

import React, { useRef, useState } from "react";
import {
  Terminal,
  Radar,
  Globe,
  Bug,
  Fingerprint,
  UploadCloud,
  Loader2,
} from "lucide-react";
import TelemetryDock, { LogEntry, LogLevel } from "./TelemetryDock";

export interface ToolConfig {
  tool: "scanner" | "ip" | "cve" | "mac" | "playbook";
  title: string;
  label: string;
  description: string;
  placeholder: string;
  defaultValue: string;
}

interface SidebarProps {
  toolConfigs: Record<string, ToolConfig>;
  onSelectTool: (config: ToolConfig) => void;
  onFileUpload: (file: File) => void;
  fileUploadLoading: boolean;
  logs: LogEntry[];
  logFilter: "ALL" | LogLevel;
  onFilterChange: (filter: "ALL" | LogLevel) => void;
}

export default function Sidebar({
  toolConfigs,
  onSelectTool,
  onFileUpload,
  fileUploadLoading,
  logs,
  logFilter,
  onFilterChange,
}: SidebarProps) {
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      onFileUpload(file);
      e.target.value = "";
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      onFileUpload(e.dataTransfer.files[0]);
    }
  };

  return (
    <div className="flex flex-col gap-5">
      {/* Triage Tool Arsenal Box */}
      <div className="surface-panel p-4">
        <div className="flex items-center justify-between pb-2.5 mb-3 border-b border-[var(--border-subtle)]">
          <div>
            <h2 className="font-heading font-semibold text-xs text-[var(--text-high)] uppercase tracking-wide">
              Triage Tool Arsenal
            </h2>
            <p className="text-[0.68rem] text-[var(--text-muted)] mt-0.5">
              Launch individual intelligence enrichment modules
            </p>
          </div>
          <Terminal className="w-4 h-4 text-[var(--accent-light)]" />
        </div>

        <div className="space-y-2">
          {/* Tool 1 */}
          <button
            onClick={() => onSelectTool(toolConfigs.scanner)}
            className="tool-arsenal-button group cursor-pointer"
          >
            <div className="flex items-center gap-3">
              <div className="w-7 h-7 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] flex items-center justify-center shrink-0 group-hover:border-[var(--accent-light)] transition-colors">
                <Radar className="w-4 h-4 text-[var(--accent-light)]" />
              </div>
              <div className="text-left">
                <div className="font-medium text-[0.82rem] text-[var(--text-high)] group-hover:text-white transition-colors">
                  Network Traffic Anomaly Scan
                </div>
                <div className="text-[0.68rem] text-[var(--text-muted)]">
                  Keras autoencoder MSE threshold scoring
                </div>
              </div>
            </div>
          </button>

          {/* Tool 2 */}
          <button
            onClick={() => onSelectTool(toolConfigs.ip)}
            className="tool-arsenal-button group cursor-pointer"
          >
            <div className="flex items-center gap-3">
              <div className="w-7 h-7 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] flex items-center justify-center shrink-0 group-hover:border-[var(--accent-light)] transition-colors">
                <Globe className="w-4 h-4 text-[var(--accent-light)]" />
              </div>
              <div className="text-left">
                <div className="font-medium text-[0.82rem] text-[var(--text-high)] group-hover:text-white transition-colors">
                  VirusTotal Threat Intelligence
                </div>
                <div className="text-[0.68rem] text-[var(--text-muted)]">
                  IP reputation &amp; malicious score attribution
                </div>
              </div>
            </div>
          </button>

          {/* Tool 3 */}
          <button
            onClick={() => onSelectTool(toolConfigs.cve)}
            className="tool-arsenal-button group cursor-pointer"
          >
            <div className="flex items-center gap-3">
              <div className="w-7 h-7 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] flex items-center justify-center shrink-0 group-hover:border-[var(--accent-light)] transition-colors">
                <Bug className="w-4 h-4 text-[var(--accent-light)]" />
              </div>
              <div className="text-left">
                <div className="font-medium text-[0.82rem] text-[var(--text-high)] group-hover:text-white transition-colors">
                  NIST NVD CVE Advisory
                </div>
                <div className="text-[0.68rem] text-[var(--text-muted)]">
                  CVSS score &amp; vulnerability metrics
                </div>
              </div>
            </div>
          </button>

          {/* Tool 4 */}
          <button
            onClick={() => onSelectTool(toolConfigs.mac)}
            className="tool-arsenal-button group cursor-pointer"
          >
            <div className="flex items-center gap-3">
              <div className="w-7 h-7 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] flex items-center justify-center shrink-0 group-hover:border-[var(--accent-light)] transition-colors">
                <Fingerprint className="w-4 h-4 text-[var(--accent-light)]" />
              </div>
              <div className="text-left">
                <div className="font-medium text-[0.82rem] text-[var(--text-high)] group-hover:text-white transition-colors">
                  Hardware OUI Resolution
                </div>
                <div className="text-[0.68rem] text-[var(--text-muted)]">
                  IEEE MAC manufacturer mapping
                </div>
              </div>
            </div>
          </button>
        </div>
      </div>

      {/* Tool 5: Drag-and-Drop Capture Ingestion (.pcap / .csv) */}
      <div className="surface-panel p-4">
        <div className="text-[0.68rem] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2 flex items-center justify-between">
          <span>Capture Stream Ingestion</span>
          <span className="text-[var(--accent-light)] font-semibold">ONLINE</span>
        </div>

        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => !fileUploadLoading && fileInputRef.current?.click()}
          className={`p-3 rounded-md border border-dashed transition-all cursor-pointer flex items-center gap-3 ${
            isDragging
              ? "border-[var(--accent-light)] bg-[var(--accent-primary)]/15 scale-[1.01]"
              : "border-[var(--border-distinct)] bg-[var(--surface-elevated)]/40 hover:border-[var(--accent-light)]"
          } ${fileUploadLoading ? "opacity-75 cursor-not-allowed" : ""}`}
        >
          <input
            type="file"
            ref={fileInputRef}
            accept=".pcap,.pcapng,.csv"
            className="hidden"
            onChange={handleFileUpload}
          />

          <div className="w-8 h-8 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] flex items-center justify-center shrink-0">
            {fileUploadLoading ? (
              <Loader2 className="w-4 h-4 text-[var(--accent-light)] animate-spin" />
            ) : (
              <UploadCloud className="w-4 h-4 text-[var(--accent-light)]" />
            )}
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <span className="font-medium text-[0.82rem] text-[var(--text-high)] truncate">
                Ingest Traffic Capture
              </span>
              <span className="font-mono text-[0.58rem] px-1.5 py-0.5 rounded bg-black/40 text-[var(--accent-light)] border border-[var(--border-subtle)] shrink-0 ml-1">
                .pcap / .csv
              </span>
            </div>
            <div className="text-[0.68rem] text-[var(--text-muted)] mt-0.5 leading-snug">
              {fileUploadLoading
                ? "Reconstructing flows and scoring anomalies..."
                : "Drag & drop packet capture for live flow reconstruction & anomaly scoring."}
            </div>
          </div>
        </div>
      </div>

      {/* System Telemetry Log Dock */}
      <TelemetryDock
        logs={logs}
        filter={logFilter}
        onFilterChange={onFilterChange}
      />
    </div>
  );
}
