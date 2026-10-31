/**
 * CYBERSICKER OASIS STIX 2.1 Bundle Exporter
 * Generates standards-compliant STIX 2.1 JSON objects (identity, incident, indicator, observed-data, relationship)
 * and triggers immediate client-side browser file download.
 */

function generateUUID(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export interface Stix21BundleOptions {
  ip?: string | null;
  cve?: string | null;
  verdict?: string;
  notes?: string;
  indicators?: string[];
  title?: string;
}

export interface StixBundle {
  type: "bundle";
  id: string;
  spec_version: string;
  objects: any[];
}

/**
 * Creates a valid OASIS STIX 2.1 bundle from session indicators and incident details.
 */
export function createStix21Bundle({
  ip = null,
  cve = null,
  verdict = "MALICIOUS",
  notes = "",
  indicators = [],
  title = "Multi-Vector SOC Incident Triage"
}: Stix21BundleOptions = {}): StixBundle {
  const timestamp = new Date().toISOString();
  const identityId = `identity--${generateUUID()}`;
  const incidentId = `incident--${generateUUID()}`;

  const objects: any[] = [];

  // 1. Identity Object (CYBERSICKER Defense Platform)
  objects.push({
    type: "identity",
    spec_version: "2.1",
    id: identityId,
    created: timestamp,
    modified: timestamp,
    name: "CYBERSICKER Autonomous Blue-Team SOC Workbench",
    description: "Automated neural autoencoder & enriched threat intelligence triage engine.",
    identity_class: "system",
    sectors: ["cybersecurity", "defense", "technology"]
  });

  // 2. Incident Object
  objects.push({
    type: "incident",
    spec_version: "2.1",
    id: incidentId,
    created: timestamp,
    modified: timestamp,
    name: title,
    description: notes || `Automated triage report with security verdict: ${verdict}.`,
    confidence: verdict === "MALICIOUS" ? 95 : verdict === "SUSPICIOUS" ? 70 : 15
  });

  // 3. Indicator Objects
  const indicatorIds: string[] = [];

  // IPv4 Indicator
  if (ip) {
    const ipIndId = `indicator--${generateUUID()}`;
    indicatorIds.push(ipIndId);
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id: ipIndId,
      created: timestamp,
      modified: timestamp,
      name: `Malicious Host Indicator: ${ip}`,
      description: `Observed anomalous network entity flagged as ${verdict}.`,
      indicator_types: ["malicious-activity", "anomalous-activity"],
      pattern: `[ipv4-addr:value = '${ip}']`,
      pattern_type: "stix",
      pattern_version: "2.1",
      valid_from: timestamp
    });
  }

  // CVE Indicator
  if (cve) {
    const cveIndId = `indicator--${generateUUID()}`;
    indicatorIds.push(cveIndId);
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id: cveIndId,
      created: timestamp,
      modified: timestamp,
      name: `Vulnerability Advisory: ${cve}`,
      description: `Disclosed vulnerability linked to incident vector.`,
      indicator_types: ["vulnerability"],
      pattern: `[vulnerability:name = '${cve}']`,
      pattern_type: "stix",
      pattern_version: "2.1",
      valid_from: timestamp
    });
  }

  // Generic Additional Indicators
  if (Array.isArray(indicators)) {
    indicators.forEach((ind) => {
      if (!ind || ind === ip || ind === cve) return;
      const genericIndId = `indicator--${generateUUID()}`;
      indicatorIds.push(genericIndId);
      objects.push({
        type: "indicator",
        spec_version: "2.1",
        id: genericIndId,
        created: timestamp,
        modified: timestamp,
        name: `Observed Artifact: ${ind}`,
        indicator_types: ["anomalous-activity"],
        pattern: `[domain-name:value = '${ind}']`,
        pattern_type: "stix",
        pattern_version: "2.1",
        valid_from: timestamp
      });
    });
  }

  // 4. Observed-Data Object
  const observedDataId = `observed-data--${generateUUID()}`;
  objects.push({
    type: "observed-data",
    spec_version: "2.1",
    id: observedDataId,
    created: timestamp,
    modified: timestamp,
    first_observed: timestamp,
    last_observed: timestamp,
    number_observed: 1,
    objects: {
      "0": {
        type: "network-traffic",
        dst_ref: ip ? "1" : undefined
      },
      ...(ip
        ? {
            "1": {
              type: "ipv4-addr",
              value: ip
            }
          }
        : {})
    }
  });

  // 5. Relationship Objects (Indicator indicates Incident)
  indicatorIds.forEach((indId) => {
    objects.push({
      type: "relationship",
      spec_version: "2.1",
      id: `relationship--${generateUUID()}`,
      created: timestamp,
      modified: timestamp,
      relationship_type: "indicates",
      source_ref: indId,
      target_ref: incidentId
    });
  });

  // Top-Level Bundle Envelope
  return {
    type: "bundle",
    id: `bundle--${generateUUID()}`,
    spec_version: "2.1",
    objects
  };
}

/**
 * Triggers an immediate browser file download for a STIX 2.1 JSON bundle.
 */
export function downloadStix21Bundle(bundle: StixBundle | Record<string, any>, filename: string = "cybersicker_stix21_export.json"): void {
  if (typeof window === "undefined" || typeof document === "undefined") {
    return;
  }
  const jsonStr = JSON.stringify(bundle, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
