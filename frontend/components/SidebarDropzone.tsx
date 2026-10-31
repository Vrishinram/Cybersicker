"use client";

import React, { useRef, useState } from "react";
import { UploadCloud, Loader2 } from "lucide-react";

interface SidebarDropzoneProps {
  onFileSelected: (file: File) => void;
  isLoading: boolean;
}

export default function SidebarDropzone({
  onFileSelected,
  isLoading,
}: SidebarDropzoneProps) {
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

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
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      onFileSelected(file);
    }
  };

  const handleClick = () => {
    if (!isLoading) {
      fileInputRef.current?.click();
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      onFileSelected(file);
      // Reset input value so the same file can be chosen again if needed
      e.target.value = "";
    }
  };

  return (
    <div className="surface-panel p-4">
      <div className="text-[0.68rem] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2 flex items-center justify-between">
        <span>Capture Stream Ingestion</span>
        <span className="text-[var(--accent-light)] font-semibold">ONLINE</span>
      </div>

      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={handleClick}
        className={`p-3 rounded-md border border-dashed transition-all cursor-pointer flex items-center gap-3 ${
          isDragging
            ? "border-[var(--accent-light)] bg-[var(--accent-primary)]/15 scale-[1.01]"
            : "border-[var(--border-distinct)] bg-[var(--surface-elevated)]/40 hover:border-[var(--accent-light)]"
        } ${isLoading ? "opacity-75 cursor-not-allowed" : ""}`}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleInputChange}
          accept=".pcap,.pcapng,.csv"
          className="hidden"
          disabled={isLoading}
        />

        <div className="w-8 h-8 rounded bg-[var(--surface-elevated)] border border-[var(--border-distinct)] flex items-center justify-center shrink-0">
          {isLoading ? (
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
            {isLoading
              ? "Reconstructing flows and scoring anomalies..."
              : "Drag & drop packet capture for live flow reconstruction & anomaly scoring."}
          </div>
        </div>
      </div>
    </div>
  );
}

