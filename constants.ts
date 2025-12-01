
import { EmailData, LogEntry } from "./types";

const FIRST_NAMES = ["Alice", "Bob", "Charlie", "Diana", "Eve"];
const SENDER_POOL = [
  "security-update@g00gle-support.com", 
  "boss@company.com", 
  "newsletter@tech.com", 
  "admin@microsoft-verify.net",
  "hr-payroll@company-internal.com"
];
const SUBJECT_POOL = [
  "URGENT: Update your password",
  "Project Update Q3",
  "Weekly Newsletter",
  "Invoice #9921 Overdue",
  "Lunch meeting?"
];

export const generateMockEmail = (): EmailData => {
  const isMalicious = Math.random() > 0.6;
  const sender = isMalicious ? SENDER_POOL[Math.floor(Math.random() * SENDER_POOL.length)] : "colleague@company.com";
  const subject = isMalicious ? SUBJECT_POOL[Math.floor(Math.random() * SUBJECT_POOL.length)] : "Meeting notes";
  
  let body = "Please review the attached documents.";
  if (isMalicious) body += " Click here immediately or your account will be suspended. 192.168.1.5";

  return {
    id: `email_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    sender,
    subject,
    body,
    attachment_hash: isMalicious ? (Math.random() > 0.5 ? "malicious_hash_123" : "unknown_hash") : "clean_hash_000",
    timestamp: new Date().toLocaleTimeString()
  };
};

export const generateMockLog = (user: string): LogEntry => {
  const actions: LogEntry['action'][] = ['login', 'email_open', 'file_download', 'data_exfiltration'];
  const action = actions[Math.floor(Math.random() * actions.length)];
  
  return {
    timestamp: new Date().toLocaleTimeString(),
    user,
    action,
    ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
    size_mb: action === 'data_exfiltration' ? Math.floor(Math.random() * 6000) : 0,
    dest_ip: action === 'data_exfiltration' ? "45.22.19.11" : undefined
  };
};

// --- NEW ENTERPRISE SOURCE SIMULATORS ---

export const generateInfrastructureLog = () => {
  const sources = [
    { type: 'AWS CloudTrail', event: 'ConsoleLogin', msg: 'Root account login detected from non-compliant IP' },
    { type: 'AWS CloudTrail', event: 'S3BucketPublic', msg: 'S3 Bucket "corp-finance" policy changed to PUBLIC' },
    { type: 'CrowdStrike', event: 'ProcessRollback', msg: 'Suspicious process "powershell.exe" terminated by Falcon Sensor' },
    { type: 'CrowdStrike', event: 'IOAM', msg: 'Indicator of Attack (IOA) blocked: Credential Dumping' },
    { type: 'Palo Alto FW', event: 'ThreatDetected', msg: 'Spyware Command & Control traffic blocked on port 443' },
    { type: 'Splunk', event: 'FailedAuth', msg: 'Repeated failed login attempts (Brute Force) on SSH Server' }
  ];

  const rand = sources[Math.floor(Math.random() * sources.length)];
  return `[${rand.type}] ${rand.event}: ${rand.msg}`;
};
