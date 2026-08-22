import type { Metadata } from "next";
import "./globals.css";

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
        className="antialiased min-h-screen"
      >
      {/* Scan-line overlay */}
        <div className="scanline-overlay" />
      {children}
      </body>
    </html>
  );
}
