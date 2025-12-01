# Project Submission: S.H.I.E.L.D.

## 1. The Problem: The SOC "Burnout" Crisis
Security Operations Centers (SOCs) are currently facing a data crisis. The average enterprise generates over **10,000 security logs per day**. 
*   **Alert Fatigue:** 95% of these logs are false positives or low-priority noise. Human analysts burn out trying to manually review them.
*   **The "Swivel Chair" Effect:** To investigate a single potential threat, an analyst must switch between 5-10 distinct tools (Email Gateway, SIEM, Firewall logs, Threat Intelligence feeds, Detonation Sandboxes).
*   **The Cost of AI:** While LLMs are powerful, sending every single system log to a paid model API is economically impossible for large enterprises.

## 2. The Solution: S.H.I.E.L.D.
**Secure Heuristic Intelligence for Event Logging & Defense (S.H.I.E.L.D.)** is an autonomous **Level 1 SOC Analyst Agent**. 

It is not just a dashboard; it is an agentic workflow engine that ingests raw data, understands context, and automates the triage process. It acts as a force multiplier, handling the high-volume, low-complexity tasks so human analysts can focus on critical threats. It consolidates the entire investigation—from detection to forensics—into a "Single Pane of Glass."

## 3. Architecture & Technical Implementation
My solution demonstrates the power of a **Sequential & Parallel Multi-Agent Architecture**:

### A. The "Tiered Intelligence" Pipeline (Sequential Agents)
To solve the economic challenge of using AI at scale, I built a tiered pipeline:
1.  **Agent 1: Sentinel (Heuristic)** 
    *   *Role:* Speed & Cost-Efficiency.
    *   *Tech:* Uses RegEx and pattern matching to instantly filter known spam or obvious spoofing. Cost: $0. Latency: 5ms.
2.  **Agent 2: Cognitive Core (Generative AI)**
    *   *Role:* Reasoning & Context.
    *   *Tech:* Powered by **Google Gemini 2.5 Flash**. It handles the "gray area" threats that rules miss.
    *   *Tools:* It utilizes **Google Search Grounding** to verify if a suspicious subject line matches active real-world phishing campaigns, effectively "Googling the threat" just like a human analyst would.

### B. Parallel Processing (Parallel Agents)
Once a threat is suspected, the system splits execution:
*   **Malware Agent:** Simulates detonating attachments in a sandbox to check file hashes.
*   **Insider Threat Agent:** simultaneously scans internal user logs for data exfiltration patterns.
These run concurrently (`Promise.all`), reducing the Mean Time to Respond (MTTR).

### C. State & Memory (Long-Term Memory)
I implemented a `MemoryBank` service to persist state.
*   If an IP or Sender is marked malicious, it is added to the Memory Bank.
*   Future encounters with this entity bypass the LLM and are auto-blocked by the Sentinel, demonstrating **Learning over Time**.

### D. Human-in-the-Loop (Trust Architecture)
To bridge the trust gap, I built a **Confidence Threshold Protocol**.
*   **Score > 80:** Auto-Block.
*   **Score < 20:** Auto-Allow.
*   **Score 50-75 (Ambiguous):** The Agent **pauses execution** and summons a human operator via the UI. This ensures the AI never blocks legitimate business traffic due to hallucinations.

## 4. Project Journey
This project began as a simple Python script designed to parse CSV logs. I realized that a text-based output could not capture the complexity of a modern SOC. 

I migrated the logic to a **React-based "Cyberpunk" Interface** to visualize the AI's "brain" (the *ScannerVisual* component). The biggest challenge was moving from mock data to real data. I overcame this by building a **Dual-Mode Ingestion Engine** that can seamlessly switch between "Simulation Mode" (for demos) and "Live Mode" (using the Gmail API to scan a real inbox).

The final result is a platform that feels alive—a true partner to the security analyst, rather than just another tool.