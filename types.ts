
export interface EmailData {
  id: string;
  subject: string;
  sender: string;
  body: string;
  attachment_hash: string;
  timestamp: string;
}

export interface LogEntry {
  timestamp: string;
  user: string;
  action: 'login' | 'email_open' | 'file_download' | 'data_exfiltration';
  ip?: string;
  location?: string;
  dest_ip?: string;
  size_mb?: number;
  file_hash?: string;
  details?: string;
}

export interface ThreatAnalysis {
  score: number;
  is_phishing: boolean;
  confidence: number;
  analysis: string;
  reasons: string[];
  agentUsed: 'SENTINEL_HEURISTIC' | 'COGNITIVE_GEMINI' | 'MEMORY_RECALL';
  groundingUrls?: string[];
  evaluation?: string; // New: Agent Self-Reflection
}

export interface ScanResult {
  id: string;
  email: EmailData;
  phishingAnalysis: ThreatAnalysis;
  malwareVerdict: 'clean' | 'malicious';
  actionTaken: 'MONITOR' | 'ISOLATE_HOST' | 'LOCK_AND_BLOCK' | 'SAFE' | 'ESCALATED' | 'REVIEW_REQUIRED' | 'MANUAL_BLOCK' | 'MANUAL_ALLOW';
  timestamp: string;
  parallelResults?: {
    malware: any;
    insider: any;
  };
}

export enum SecurityStatus {
  SECURE = 'SECURE',
  ELEVATED = 'ELEVATED',
  CRITICAL = 'CRITICAL',
  INTERVENTION = 'INTERVENTION'
}

// --- NEW FORENSICS & VULN SCAN TYPES ---

export interface Vulnerability {
  cve: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  component: string;
}

export interface Asset {
  id: string;
  name: string;
  ip: string;
  type: 'SERVER' | 'WORKSTATION' | 'IOT';
  status: 'ONLINE' | 'OFFLINE' | 'COMPROMISED';
  lastScan: string | null;
  vulns: Vulnerability[];
}

export interface ForensicArtifact {
  id: string;
  type: 'MEMORY_DUMP' | 'PCAP' | 'DISK_IMAGE' | 'LOG_FILE';
  source: string;
  size: string;
  status: 'PENDING' | 'ANALYZING' | 'CLEAN' | 'INFECTED';
  findings: string[];
}

// --- NEW NETWORK & IDS TYPES ---

export interface ACLRule {
  id: number;
  sequence: number;
  action: 'PERMIT' | 'DENY';
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'IP';
  source: string;
  destination: string;
  port: string;
}

export interface RouteEntry {
  destination: string;
  gateway: string;
  interface: string;
  metric: number;
  type: 'STATIC' | 'OSPF' | 'BGP' | 'CONNECTED';
}

export interface IDSSensor {
  id: string;
  name: string;
  vendor: 'FireEye' | 'Sourcefire' | 'Carbon Black';
  version: string;
  status: 'ONLINE' | 'OFFLINE' | 'UPDATING';
  lastUpdate: string;
  events24h: number;
}

// --- NEW IAM & ENDPOINT TYPES ---

export interface IdentityProfile {
  user: string;
  role: 'ADMIN' | 'USER' | 'SERVICE_ACCOUNT';
  mfaStatus: 'ENFORCED' | 'NOT_CONFIGURED';
  lastLogin: string;
  privilegeLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  riskScore: number;
  violations: string[];
}

export interface EndpointDevice {
  id: string;
  hostname: string;
  os: string;
  encryptionStatus: 'ENCRYPTED' | 'DECRYPTED'; // Encryption
  hardeningScore: number; // Security Hardening
  edrStatus: 'ACTIVE' | 'MISSING';
  compliant: boolean;
}

// --- NEW FRAMEWORK TYPES (STRIDE, LINDDUN, etc) ---

export interface StrideProfile {
  assetName: string;
  spoofing: number;
  tampering: number;
  repudiation: number;
  infoDisclosure: number;
  dos: number;
  elevation: number;
}

export interface LinddunProfile {
  assetName: string;
  linkability: number;
  identifiability: number;
  nonRepudiation: number;
  detectability: number;
  disclosure: number;
  unawareness: number;
  nonCompliance: number;
}

export interface RiskEntry {
  id: string;
  threat: string;
  impact: 'HIGH' | 'MEDIUM' | 'LOW';
  probability: 'HIGH' | 'MEDIUM' | 'LOW';
  framework: 'OCTAVE' | 'PASTA';
  status: 'MITIGATED' | 'OPEN';
}
