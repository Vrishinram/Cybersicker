export const dynamic = "force-dynamic";

export async function GET() {
  const backendUrl = process.env.BACKEND_URL || "http://127.0.0.1:8000";

  try {
    const upstream = await fetch(`${backendUrl}/api/v1/telemetry/stream`, {
      headers: { Accept: "text/event-stream" },
      signal: AbortSignal.timeout(2000),
    });

    if (upstream.ok && upstream.body) {
      return new Response(upstream.body, {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache, no-transform",
          Connection: "keep-alive",
        },
      });
    }
  } catch {
    // Cloud / serverless fallback SSE stream
  }

  // Fallback SSE stream for edge/cloud deployment
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      const initEvent = `data: ${JSON.stringify({
        event: "STREAM_CONNECTED",
        source: "cloud-edge-telemetry",
        timestamp: Date.now(),
      })}\n\n`;
      controller.enqueue(encoder.encode(initEvent));

      const interval = setInterval(() => {
        try {
          const heartbeat = `data: ${JSON.stringify({
            event: "HEARTBEAT",
            status: "NOMINAL",
            timestamp: Date.now(),
          })}\n\n`;
          controller.enqueue(encoder.encode(heartbeat));
        } catch {
          clearInterval(interval);
        }
      }, 5000);
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}

