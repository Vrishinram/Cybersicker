import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CYBERSICKER — IoT Anomaly Scanner & Threat Intelligence Console",
  description:
    "Open-source blue-team console: Deep neural autoencoder anomaly scoring, live VirusTotal & NVD enrichment, and automated incident response.",
  icons: {
    icon: "/logo.png",
    shortcut: "/logo.png",
    apple: "/logo.png",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body suppressHydrationWarning className="antialiased min-h-screen">
        {children}
      </body>
    </html>
  );
}
