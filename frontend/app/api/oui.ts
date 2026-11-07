export type OUIEntry = {
  vendor: string;
  note: string;
  category: string;
};

export const OUI_REGISTRY: Record<string, OUIEntry> = {
  // Raspberry Pi Foundation (IoT SBC)
  B827EB: {
    vendor: "Raspberry Pi Foundation",
    note: "Identified low-cost IoT single-board computer; inspect unauthorized local network presence.",
    category: "IoT SBC",
  },
  DCA632: {
    vendor: "Raspberry Pi Foundation",
    note: "Identified low-cost IoT single-board computer; inspect unauthorized local network presence.",
    category: "IoT SBC",
  },
  E45F01: {
    vendor: "Raspberry Pi Foundation",
    note: "Identified low-cost IoT single-board computer; inspect unauthorized local network presence.",
    category: "IoT SBC",
  },
  "28CDC1": {
    vendor: "Raspberry Pi Foundation",
    note: "Identified low-cost IoT single-board computer; inspect unauthorized local network presence.",
    category: "IoT SBC",
  },

  // Espressif Systems (ESP8266 / ESP32 IoT Microcontroller)
  FC65DE: {
    vendor: "Espressif Inc.",
    note: "Identified low-power ESP32/ESP8266 IoT microcontroller; check for insecure MQTT/CoAP or exposed sensor firmware.",
    category: "IoT Microcontroller",
  },
  "240AC4": {
    vendor: "Espressif Inc.",
    note: "Identified low-power ESP32/ESP8266 IoT microcontroller; check for insecure MQTT/CoAP or exposed sensor firmware.",
    category: "IoT Microcontroller",
  },
  "30AEA4": {
    vendor: "Espressif Inc.",
    note: "Identified low-power ESP32/ESP8266 IoT microcontroller; check for insecure MQTT/CoAP or exposed sensor firmware.",
    category: "IoT Microcontroller",
  },
  A4CF12: {
    vendor: "Espressif Inc.",
    note: "Identified low-power ESP32/ESP8266 IoT microcontroller; check for insecure MQTT/CoAP or exposed sensor firmware.",
    category: "IoT Microcontroller",
  },
  "84F3EB": {
    vendor: "Espressif Inc.",
    note: "Identified low-power ESP32/ESP8266 IoT microcontroller; check for insecure MQTT/CoAP or exposed sensor firmware.",
    category: "IoT Microcontroller",
  },

  // Google LLC (Smart Device / Nest)
  "001A11": {
    vendor: "Google, LLC",
    note: "Identified smart home/Nest or Google hardware endpoint; inspect IoT perimeter isolation rules.",
    category: "Smart Device / Nest",
  },
  F4F5D8: {
    vendor: "Google, LLC",
    note: "Identified smart home/Nest or Google hardware endpoint; inspect IoT perimeter isolation rules.",
    category: "Smart Device / Nest",
  },
  D86C63: {
    vendor: "Google, LLC",
    note: "Identified smart home/Nest or Google hardware endpoint; inspect IoT perimeter isolation rules.",
    category: "Smart Device / Nest",
  },

  // VMware Inc. (Virtual Machine Interface)
  "000C29": {
    vendor: "VMware, Inc.",
    note: "Identified VMware ESXi/Workstation virtual network adapter; confirm virtualization host legitimacy.",
    category: "Virtualization Interface",
  },
  "005056": {
    vendor: "VMware, Inc.",
    note: "Identified VMware ESXi/Workstation virtual network adapter; confirm virtualization host legitimacy.",
    category: "Virtualization Interface",
  },
  "000569": {
    vendor: "VMware, Inc.",
    note: "Identified VMware ESXi/Workstation virtual network adapter; confirm virtualization host legitimacy.",
    category: "Virtualization Interface",
  },

  // Parallels Inc. (Virtual Machine Interface)
  "001C42": {
    vendor: "Parallels, Inc.",
    note: "Identified Parallels desktop virtualization guest adapter.",
    category: "Virtualization Interface",
  },

  // Microsoft Corporation (Virtual Adapter)
  "00155D": {
    vendor: "Microsoft Corporation",
    note: "Identified Microsoft Hyper-V virtual network interface or Windows endpoint.",
    category: "Virtualization Interface",
  },

  // Cisco Systems Inc. (Enterprise Gateway)
  "001A2B": {
    vendor: "Cisco Systems, Inc.",
    note: "Verified enterprise switch, router, or core network infrastructure gateway.",
    category: "Enterprise Gateway",
  },
  "00000C": {
    vendor: "Cisco Systems, Inc.",
    note: "Verified enterprise switch, router, or core network infrastructure gateway.",
    category: "Enterprise Gateway",
  },
  "000142": {
    vendor: "Cisco Systems, Inc.",
    note: "Verified enterprise switch, router, or core network infrastructure gateway.",
    category: "Enterprise Gateway",
  },
  "000143": {
    vendor: "Cisco Systems, Inc.",
    note: "Verified enterprise switch, router, or core network infrastructure gateway.",
    category: "Enterprise Gateway",
  },

  // Apple Inc.
  "3C5AB4": {
    vendor: "Apple, Inc.",
    note: "Identified Apple macOS/iOS endpoint; verify corporate MDM profile.",
    category: "Workstation / Mobile",
  },
  ACBC32: {
    vendor: "Apple, Inc.",
    note: "Identified Apple macOS/iOS endpoint; verify corporate MDM profile.",
    category: "Workstation / Mobile",
  },
  F8FFC2: {
    vendor: "Apple, Inc.",
    note: "Identified Apple macOS/iOS endpoint; verify corporate MDM profile.",
    category: "Workstation / Mobile",
  },

  // Intel
  "001E67": {
    vendor: "Intel Corporate",
    note: "Verified Intel gigabit ethernet/Wi-Fi adapter.",
    category: "Enterprise NIC",
  },

  // TP-Link
  "50C7BF": {
    vendor: "TP-Link Corporation",
    note: "Identified TP-Link smart home Wi-Fi smart plug/switch.",
    category: "Consumer IoT",
  },
};

export function resolveMacOui(macAddress: string) {
  const clean = macAddress.replace(/[^0-9A-Fa-f]/g, "").toUpperCase();
  if (clean.length < 6) {
    return {
      mac: macAddress,
      oui: clean,
      vendor: "INVALID_MAC",
      deviceNote: "Invalid MAC address format (fewer than 6 hex digits).",
      category: "Invalid",
    };
  }
  const oui = clean.slice(0, 6);
  const formattedMac = clean
    .match(/.{1,2}/g)
    ?.slice(0, 6)
    .join(":") || macAddress;

  if (OUI_REGISTRY[oui]) {
    const entry = OUI_REGISTRY[oui];
    return {
      mac: formattedMac,
      oui,
      vendor: entry.vendor,
      deviceNote: entry.note,
      category: entry.category,
    };
  }

  const firstByte = parseInt(oui.slice(0, 2), 16);
  if ((firstByte & 0x02) !== 0 || oui === "AABBCC") {
    return {
      mac: formattedMac,
      oui,
      vendor: "Locally Administered / Private Unregistered MAC",
      deviceNote: "Locally administered address (LAA) or randomized/spoofed MAC; treat as high-risk untrusted endpoint.",
      category: "Randomized / Spoofed",
    };
  }

  return {
    mac: formattedMac,
    oui,
    vendor: "Unknown Manufacturer",
    deviceNote: "Unregistered or obscure hardware vendor; monitor connection telemetry for abnormal egress traffic.",
    category: "Unregistered",
  };
}

