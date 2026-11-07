import { NextResponse } from "next/server";
import { POST as ipCheckPost } from "../tools/ip-check/route";
import { POST as cveLookupPost } from "../tools/cve-lookup/route";
import { POST as macLookupPost } from "../tools/mac-lookup/route";
import { POST as scanPost } from "../tools/scan/route";

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const tool = (body.tool || "").toLowerCase();
  const arg = (body.argument || "").trim();

  try {
    if (tool === "ip") {
      const synthetic = new Request(req.url, {
        method: "POST",
        headers: req.headers,
        body: JSON.stringify({ ip_address: arg || "185.220.101.43" }),
      });
      return ipCheckPost(synthetic);
    }

    if (tool === "cve") {
      const synthetic = new Request(req.url, {
        method: "POST",
        headers: req.headers,
        body: JSON.stringify({ cve_id: arg || "CVE-2024-3094" }),
      });
      return cveLookupPost(synthetic);
    }

    if (tool === "mac") {
      const synthetic = new Request(req.url, {
        method: "POST",
        headers: req.headers,
        body: JSON.stringify({ mac_address: arg || "B8:27:EB:AA:BB:CC" }),
      });
      return macLookupPost(synthetic);
    }

    if (tool === "scanner" || tool === "scan") {
      const synthetic = new Request(req.url, {
        method: "POST",
        headers: req.headers,
        body: JSON.stringify({ filepath: arg || "KDDTrain+.txt" }),
      });
      return scanPost(synthetic);
    }

    if (tool === "playbook") {
      return NextResponse.json({
        success: true,
        result: JSON.stringify({
          event: "CHROMA_RAG_HIT",
          query: arg || "Botnet infection containment and perimeter isolation",
          playbook_id: "SOP-001",
          title: "IoT Botnet Infection Response",
          category: "Botnet Mitigation",
          similarity_score: 0.92,
          content: "1. Isolate affected IoT network segment.\n2. Revoke active C2 connections at edge firewall.\n3. Verify device firmware and restore known-good configuration.",
          action_steps: [
            "Isolate switchport and assign to Quarantine VLAN 99",
            "Drop inbound and outbound traffic to C2 IPs on port 23/2323",
            "Flash verified vendor firmware image",
          ],
        }),
      });
    }

    return NextResponse.json({
      success: false,
      error: `Unknown tool identifier: ${tool}`,
    });
  } catch (err) {
    return NextResponse.json({
      success: false,
      error: String(err),
    });
  }
}
