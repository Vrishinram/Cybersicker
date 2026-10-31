import { NextResponse } from "next/server";
import { resolveMacOui } from "../../oui";

export async function POST(req: Request) {
  const backendUrl = process.env.BACKEND_URL || "http://127.0.0.1:8000";
  const body = await req.json().catch(() => ({}));
  try {
    const res = await fetch(`${backendUrl}/api/tools/mac-lookup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(4000),
    });
    if (res.ok) {
      const data = await res.json();
      return NextResponse.json(data);
    }
  } catch {
    // Cloud fallback
  }

  const rawMac = body.mac_address || "00:1A:2B:3C:4D:5E";
  const resolved = resolveMacOui(rawMac);

  return NextResponse.json({
    success: true,
    result: JSON.stringify({
      event: "MAC_RESOLVE",
      mac: resolved.mac,
      oui: resolved.oui,
      vendor: resolved.vendor,
      note: resolved.deviceNote,
      category: resolved.category,
    }),
  });
}
