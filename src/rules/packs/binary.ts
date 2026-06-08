import type { PatternRule, RuleDefinition } from "../types";

export const binaryRules: Record<"elf_executable_magic" | "content_type_magic_mismatch" | "elf_writable_executable_stack", RuleDefinition> = {
  elf_executable_magic: {
    id: "elf_executable_magic",
    pack: "binary-static",
    severity: "high",
    confidence: "high",
    title: "ELF executable",
    description: "Content begins with ELF executable magic bytes.",
    locationType: "binary",
    score: { base: 55, tags: ["binary"] }
  },
  content_type_magic_mismatch: {
    id: "content_type_magic_mismatch",
    pack: "binary-static",
    severity: "high",
    confidence: "high",
    title: "Content type does not match magic bytes",
    description: "Declared content type conflicts with executable magic bytes.",
    locationType: "binary",
    score: { base: 45, tags: ["binary", "obfuscation"] }
  },
  elf_writable_executable_stack: {
    id: "elf_writable_executable_stack",
    pack: "binary-static",
    severity: "high",
    confidence: "medium",
    title: "ELF requests writable executable stack",
    description: "ELF program headers include a GNU_STACK segment with write and execute permissions.",
    locationType: "binary",
    score: { base: 32, tags: ["binary"] }
  }
};

export const binaryStringRules: PatternRule[] = [
  {
    id: "iot_botnet_family_strings",
    pack: "binary-static",
    severity: "high",
    confidence: "high",
    title: "IoT botnet family strings",
    description: "Binary strings reference IoT botnet family names or architecture payload naming.",
    locationType: "binary",
    pattern: /\b(?:Mozi|mirai|gafgyt|boatnet|Mozi\.[a-z0-9])\b/i,
    score: { base: 70, tags: ["binary"] }
  },
  {
    id: "iot_device_exploit_strings",
    pack: "binary-static",
    severity: "high",
    confidence: "medium",
    title: "IoT device exploit strings",
    description: "Binary strings reference common router, camera, TR-064, HNAP, GPON, or Realtek exploitation paths.",
    locationType: "binary",
    pattern: /\b(?:gpon8080|gpon80|realtek|netgear8080|netgear80|huawei|tr064|hnap|camcrossweb|camjaws|dlink|vacron|setup\.cgi|SOAPAction:|AddPortMapping|SetNTPServers)\b/i,
    score: { base: 42, tags: ["binary"] }
  },
  {
    id: "iot_payload_dropper_commands",
    pack: "binary-static",
    severity: "high",
    confidence: "high",
    title: "IoT payload dropper commands",
    description: "Binary strings contain wget/curl, chmod, temporary directory, and shell execution payload chains.",
    locationType: "binary",
    pattern: /(?:wget|curl|busybox wget)[\s\S]{0,160}(?:chmod|\/tmp|\/var\/tmp|\/dev\/shm)[\s\S]{0,160}(?:\/bin\/sh|sh\s|\.\/|Mozi\.)/i,
    score: { base: 64, tags: ["binary", "source"] }
  },
  {
    id: "router_management_hijack_commands",
    pack: "binary-static",
    severity: "high",
    confidence: "high",
    title: "Router management hijack commands",
    description: "Binary strings contain TR-069 or router management-server hijack commands.",
    locationType: "binary",
    pattern: /(?:cfgtool|sendcmd)[\s\S]{0,240}(?:ManagementServer|MgtServer|Tr069Enable|ConnectionRequestPassword|acsMozi|127\.0\.0\.1)/i,
    score: { base: 58, tags: ["binary"] }
  },
  {
    id: "firewall_lockout_commands",
    pack: "binary-static",
    severity: "medium",
    confidence: "high",
    title: "Firewall lockout commands",
    description: "Binary strings contain iptables rules that block management, TR-069, telnet, or SSH ports.",
    locationType: "binary",
    pattern: /iptables[\s\S]{0,120}(?:DROP|--dport|--sport|--destination-port|--source-port)[\s\S]{0,80}\b(?:22|23|2323|35000|50023|7547|58000)\b/i,
    score: { base: 34, tags: ["binary"] }
  },
  {
    id: "dht_cnc_protocol_strings",
    pack: "binary-static",
    severity: "medium",
    confidence: "high",
    title: "DHT/CNC protocol strings",
    description: "Binary strings contain DHT peer protocol and command-and-control markers.",
    locationType: "binary",
    pattern: /(?:\[cnc\]|\[atk\]|\[ud\]|\[dip\]|1:q9:find_node|1:q9:get_peers|1:q13:announce_peer|info_hash20|nodes6)/i,
    score: { base: 34, tags: ["binary"] }
  }
];
