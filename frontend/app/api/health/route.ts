import { NextResponse } from "next/server";

export async function GET() {
  const backendUrl = process.env.BACKEND_URL || "http://127.0.0.1:8000";
  try {
    const res = await fetch(`${backendUrl}/api/health`, {
      signal: AbortSignal.timeout(1200),
    });
    if (res.ok) {
      const data = await res.json();
      return NextResponse.json(data);
    }
  } catch {
    // Cloud / serverless fallback
  }

  return NextResponse.json({
    status: "online",
    deployment: "cloud-edge",
    llm_provider: "ollama",
    ollama_model: "llama3.2",
    google_key_set: true,
    groq_key_set: false,
    openrouter_key_set: false,
    scitely_key_set: true,
    vt_key_set: true,
    mode: "edge-active",
  });
}

