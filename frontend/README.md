# CYBERSICKER - Frontend SOC Console

> Next.js 16 + React 19 + Tailwind CSS Blue-Team Security Operations Center Workbench  
> Production URL: [https://cybersicker-soc.vercel.app](https://cybersicker-soc.vercel.app)

---

## Architectural Highlights

- **Live Incident Console:** Multi-intent investigation feed powered by Google Gemini 2.5 Flash.
- **Conditional Active Defense Controls:** Renders `[Copy Containment Rule]` and `[Block Border Ingress]` for malicious threats, and neutral `[Inspect ASN / WHOIS]` for verified clean hosts.
- **Client-Side STIX 2.1 Export:** Generates OASIS STIX 2.1 JSON incident response bundles and triggers immediate browser download.
- **Capture Ingestion Dropzone:** Interactive drag-and-drop `.pcap`, `.pcapng`, and `.csv` packet capture ingestion with flow reconstruction and Keras Autoencoder anomaly scoring.
- **Real-Time Telemetry Dock:** Syntax-highlighted streaming log terminal with instant log level filtering (`ALL`, `INF`, `WRN`, `ERR`).
- **Session Control:** Top bar `[RESET SESSION]` action button that flushes investigation state back to initial greeting.

---

## Component Architecture

- [`components/Header.tsx`](file:///d:/Cybersicker/frontend/components/Header.tsx): Top navigation bar with live status indicators, uptime counter, and `[RESET SESSION]` button.
- [`components/Sidebar.tsx`](file:///d:/Cybersicker/frontend/components/Sidebar.tsx): Triage tool arsenal and `.pcap`/`.csv` file dropzone.
- [`components/ChatFeed.tsx`](file:///d:/Cybersicker/frontend/components/ChatFeed.tsx): Central incident chat feed with threat card parsing and contextual defense buttons.
- [`components/TelemetryDock.tsx`](file:///d:/Cybersicker/frontend/components/TelemetryDock.tsx): Terminal with JSON syntax highlighting and real-time streaming logs.
- [`app/utils/stix_exporter.ts`](file:///d:/Cybersicker/frontend/app/utils/stix_exporter.ts): OASIS STIX 2.1 JSON bundle builder and file downloader.

---

## Getting Started

```bash
# Install dependencies
npm install

# Run local development server
npm run dev

# Build for production
npm run build
npm run start
```
