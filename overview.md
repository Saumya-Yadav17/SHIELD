# S.H.I.E.L.D. Dashboard: Architectural Overview

**S.H.I.E.L.D.** is a multi-agent front-end dashboard designed for Security Operations Center (SOC) monitoring and response. This repository provides a high-level architectural guide for software architects, developers, and security engineers.

---

## Table of Contents

- [Introduction](#introduction)  
- [Core Technology Stack](#core-technology-stack)  
- [Application State Management](#application-state-management)  
- [System Services](#system-services)  
- [Agent Pipeline](#agent-pipeline)  
- [User Interface & Navigation](#user-interface--navigation)  
- [Summary](#summary)  

---

## Introduction

S.H.I.E.L.D. provides a multi-agent SOC dashboard for real-time monitoring and threat response. This document explains:

- Front-end architecture  
- State management  
- Modular services  
- Agent-based analysis workflow  

It serves as a reference for developers building and maintaining the platform.

---

## Core Technology Stack

| Technology | Role |
|-----------|------|
| **React** | Component-based UI with Hooks (`useState`, `useEffect`, `useRef`) |
| **Recharts** | Declarative charting (`BarChart`, `AreaChart`, `PieChart`) |
| **Lucide-React** | Consistent SVG icons for UI clarity and navigation |

### Component Hierarchy

- **General-Purpose Components:** `Terminal`, `StatCard`, `ScannerVisual`  
- **View Components:** `ViewNetworkOps`, `ViewVulnerabilityScanner`, `ViewUserActivity`  

Organized by domain (`Infrastructure`, `Governance`, `Forensics`) for modular SPA architecture.

---

## Application State Management

State is centralized within the `App` component using React Hooks.  

### Core System State

| Variable | Type / Default | Responsibility |
|----------|----------------|----------------|
| `isRunning` | boolean | Toggles agent pipeline |
| `currentAgent` | string | Tracks active agent |
| `pendingReview` | object/null | Holds threats needing human review |
| `processingRef` | MutableRef | Prevents concurrent pipeline runs |

### Data & Logging

| Variable | Type | Purpose |
|----------|------|---------|
| `logs` | string[] | Terminal logs |
| `scanHistory` | ScanResult[] | Recent scans |
| `currentEmail` | EmailData/null | Active email |
| `currentAnalysis` | ThreatAnalysis | Analysis results |
| `userActivityLogs` | LogEntry[] | Insider threat simulation |

### UI & Navigation

| Variable | Type / Default | Purpose |
|----------|----------------|---------|
| `activeView` | string | SPA main view |
| `isSidebarOpen` | boolean | Sidebar toggle |
| `showSettings` | boolean | Settings modal visibility |

### Dashboard Metrics

| Variable | Type | Purpose |
|----------|------|---------|
| `threatLevel` | SecurityStatus | Overall system status |
| `blockedCount` | number | Total threats blocked |
| `scannedCount` | number | Items processed |
| `activeUsers` | number | Network user count |

### External Integration

| Variable | Type | Purpose |
|----------|------|---------|
| `dataSource` | 'MOCK' / 'GMAIL' | Input source |
| `gmailToken` | string | OAuth token |
| `processedGmailIds` | Set | Prevent duplicate scans |

---

## System Services

### Shield Engine

- `runHeuristicScan` – Initial threat scoring  
- `runCognitiveScan` – Advanced analysis  
- `checkFileHash` – Malware simulation  
- `checkInsiderThreats` – Insider threat detection  

### Gmail Tool

- Fetches real Gmail messages using OAuth  
- Prevents duplicate analysis via `processedGmailIds`  

### Memory Bank

- Stores **Indicators of Compromise (IOCs)**  
- Enables instant threat recall to bypass redundant scans  

---

## Agent Pipeline

The `runAgentPipeline` function simulates a multi-stage security analysis:

1. **Pre-checks** – Prevent parallel execution  
2. **Data Ingestion** – Pulls email from mock or Gmail  
3. **SENTINEL** – Heuristic triage  
4. **COGNITIVE** – Deep analysis if risk > 20  
5. **INTERVENTION** – Human review for ambiguous threats  
6. **PARALLEL** – Malware + insider analysis concurrently  
7. **Adjudication** – Determines final action: `LOCK_AND_BLOCK`, `MONITOR`, or `SAFE`  

---

## User Interface & Navigation

### Sidebar Menu

- **Security Posture:** `EXEC_SUMMARY`, `SOC_OPS`, `RISK_ANALYSIS`  
- **Infrastructure & IDS:** `NETWORK_OPS`, `IDS_MANAGER`  
- **Incident Review:** `THREAT_INTEL`, `AUDIT`  
- **GRC & Frameworks:** `THREAT_MODEL`, `RISK_GOV`  
- **Forensics & Scans:** `VULN_SCANNER`, `FORENSICS_LAB`  
- **Identity & Endpoint:** `ACCESS`, `ENDPOINT`, `USER_ACTIVITY`  
- **Integrations:** `OSS_TOOLS`  

### SPA Navigation Example

```jsx
{activeView === 'SOC_OPS' && <ViewSocOps />}
