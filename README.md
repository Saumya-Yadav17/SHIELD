# S.H.I.E.L.D. - Secure Heuristic Intelligence for Event Logging & Defense

> **Capstone Project: Enterprise Agents Track**  
> *Autonomous Level 1 SOC Analyst Platform*

## 📋 Overview

**S.H.I.E.L.D.** is a Multi-Agent Security Orchestration platform designed to solve the "Alert Fatigue" crisis in modern Security Operations Centers (SOCs). 

Instead of relying solely on static rules or expensive LLM calls for every log, S.H.I.E.L.D. utilizes a **Sequential & Parallel Multi-Agent Pipeline** to triage, analyze, and mitigate threats autonomously. It acts as a "Single Pane of Glass" for enterprise security, consolidating Forensics, Network Operations, Identity Management, and GRC into one unified interface.

[Open SHIELD App](https://s-h-i-e-l-d-795860681266.us-west1.run.app)

<img width="950" height="366" alt="image" src="https://github.com/user-attachments/assets/ca7a2ccc-71f5-4063-bb17-68e81f817899" />



## 🧠 Cognitive Architecture

This agent demonstrates mastery of the following course concepts:

1.  **Sequential Multi-Agent System:**
    *   **Sentinel Agent (Agent 1):** A high-speed, low-cost heuristic engine that filters 90% of noise using regex patterns (Sender Spoofing, Urgency, Financial Triggers).
    *   **Cognitive Core (Agent 2):** Powered by **Gemini 2.5 Flash**. Activates only for high-risk/ambiguous threats. Uses **Reasoning** to evaluate context.
    *   **Parallel Agents (Agent 3 & 4):** Once a threat is suspected, the **Malware Sandbox Agent** and **Insider Threat Agent** run simultaneously to correlate file hashes and internal logs.

2.  **Tool Use & Grounding:**
    *   **Google Search Grounding:** The Cognitive Agent verifies sender reputation and cross-references subject lines with active global phishing campaigns in real-time.
    *   **Gmail API Tool:** Can switch from "Simulation Mode" to "Live Mode" to ingest real emails from a user's inbox.

3.  **Human-in-the-Loop (HITL):**
    *   Implements a "Confidence Threshold" protocol. If the AI confidence score is between 50-75%, execution pauses, and the system requests human intervention to prevent false positives.

4.  **Long-Term Memory:**
    *   **Memory Bank Service:** Persists reputation scores for IPs, Senders, and File Hashes. Once a threat is confirmed, it is remembered globally, short-circuiting future analysis.

## 🚀 Key Features

### 🛡️ SOC Operations (Main Dashboard)
*   **Live Traffic Monitor:** Visualizes the agent's "Thinking Process" (Scanning Beam).
*   **Real-time Metrics:** Tracks Threats Blocked, Response Time, and Risk Velocity.
*   **Terminal Output:** Raw system logs mimicking a Linux security appliance.

### 🔬 Forensics Lab (Level 1)
*   **Evidence Locker:** Manages artifacts (Memory Dumps, PCAP files).
*   **Automated Triage:** Simulates running tools like **Velociraptor** and **Volatility 3** to analyze infected assets without human touch.
*   **Vulnerability Scanner:** Integration view for OpenVAS/Nmap results.

### 🌐 Network & Infrastructure
*   **NOC View:** Manage Routing Tables, VPN Tunnels, and Access Control Lists (ACLs).
*   **IDS Manager:** Unified console for FireEye, Sourcefire, and Carbon Black sensors.

### ⚖️ GRC & Risk
*   **Risk Analysis (FAIR Model):** Quantitative risk scoring with Monte Carlo forecasting.
*   **Threat Modeling:** Visualizes STRIDE and LINDDUN frameworks via Radar charts.
*   **Compliance:** Real-time ISO 27001 control monitoring.

### 🔒 Security & Identity
*   **IAM Dashboard:** Monitor User Risk Scores, MFA enforcement, and Privilege Escalation attempts.
*   **Endpoint Security:** Track Encryption status (BitLocker), EDR coverage, and Asset Hardening.

## 🛠️ Installation & Setup

### Prerequisites
*   Node.js v18+
*   A Google Cloud API Key (for Gemini models)

### Quick Start

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/your-username/shield-capstone.git
    cd shield-capstone
    ```

2.  **Install Dependencies**
    ```bash
    npm install
    ```

3.  **Set Environment Variables**
    Create a `.env` file in the root directory:
    ```env
    API_KEY=your_gemini_api_key_here
    ```

4.  **Run the Application**
    ```bash
    npm run dev
    ```

## 🎮 Usage Guide

### Simulation Mode (Default)
1.  Click the **ACTIVATE** button in the top right.
2.  The system will generate synthetic traffic (Phishing emails, AWS Logs, CrowdStrike Alerts).
3.  Watch the **Scanner Visual** to see agents handing off tasks.

### Live Gmail Mode
1.  Click the **Settings (Gear Icon)**.
2.  Select **Gmail Live API**.
3.  Paste a valid **OAuth Access Token** (obtainable via [Google OAuth Playground](https://developers.google.com/oauthplayground/) with `https://www.googleapis.com/auth/gmail.readonly` scope).
4.  Click **Save Configuration** and then **ACTIVATE**.

## 📂 Project Structure

*   `/src/services`
    *   `shieldEngine.ts`: Core logic for Sentinel, Cognitive, and Parallel agents.
    *   `memoryBank.ts`: Long-term memory service.
    *   `gmailTool.ts`: REST client for Gmail API.
*   `/src/components/views`: Modular dashboard components.
    *   `Infrastructure.tsx`: Network & IDS views.
    *   `Forensics.tsx`: Vuln Scanner & Forensics Lab.
    *   `Governance.tsx`: Risk, Compliance, Threat Models.
    *   `Ops.tsx`: Threat Intel, Audit, OSS Tools.
    *   `Security.tsx`: IAM & Endpoint views.
*   `/src/components`
    *   `ScannerVisual.tsx`: The animated "Brain" of the dashboard.
    *   `StatCard.tsx`, `Terminal.tsx`: UI Widgets.

## 📄 License
MIT License. 
