import { NextResponse } from "next/server";
import { POST as fullTriagePost } from "../full-triage/route";

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));

  // Normalize parameters to full-triage schema
  const normalized = {
    filepath: body.filepath || "KDDTrain+.txt",
    ip_address: body.ip_address || body.ip || "185.220.101.43",
    mac_address: body.mac_address || body.mac || "B8:27:EB:AA:BB:CC",
    cve_id: body.cve_id || body.cve || "CVE-2024-3094",
    incident_type: body.incident_type || body.playbook_topic || "Botnet infection containment and perimeter isolation",
  };

  const syntheticReq = new Request(req.url, {
    method: "POST",
    headers: req.headers,
    body: JSON.stringify(normalized),
  });

  return fullTriagePost(syntheticReq);
}
