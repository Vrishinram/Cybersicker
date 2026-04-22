import type { Metadata } from "next";
import { Orbitron, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const orbitron = Orbitron({
  subsets: ***REMOVED***"latin"***REMOVED***,
  variable: "--font-display",
});

const jetBrainsMono = JetBrains_Mono({
  subsets: ***REMOVED***"latin"***REMOVED***,
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: "CYBERSICKER // SOC Dashboard",
  description:
    "Autonomous IoT Blue Team Agent — Threat Detection & Response System",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        suppressHydrationWarning
        className={`${orbitron.variable} ${jetBrainsMono.variable} antialiased min-h-screen`}
      >
      ***REMOVED***/* Scan-line overlay */}
        <div className="scanline-overlay" />
      ***REMOVED***children}
      </body>
    </html>
  );
}
