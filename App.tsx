
import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, Activity, Lock, Users, Play, Pause, RefreshCw, Mail, Settings, Wifi, ExternalLink,
  LayoutDashboard, Globe, Server, UserCheck, AlertOctagon, Menu, X,
  Package, Bug, Microscope, Router, Eye, ShieldCheck, ClipboardList, Layers, Wrench
} from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, 
  AreaChart, Area, CartesianGrid, PieChart, Pie
} from 'recharts';

import { Terminal } from './components/Terminal';
import { StatCard } from './components/StatCard';
import { ScannerVisual } from './components/ScannerVisual';

import { EmailData, ScanResult, SecurityStatus, ThreatAnalysis, LogEntry, IdentityProfile, EndpointDevice } from './types';
import { runHeuristicScan, runCognitiveScan, checkFileHash, checkInsiderThreats } from './services/shieldEngine';
import { generateMockEmail, generateMockLog, generateInfrastructureLog } from './constants';
import { GmailTool } from './services/gmailTool';
import { MemoryBank } from './services/memoryBank';

// --- VIEW IMPORTS ---
import { ViewNetworkOps, ViewIDSManager } from './components/views/Infrastructure';
import { ViewVulnerabilityScanner, ViewForensicsLab } from './components/views/Forensics';
import { ViewThreatModeling, ViewRiskGovernance, ViewRiskAnalysis } from './components/views/Governance';
import { ViewAudit, ViewThreatIntel, ViewUserActivity, ViewOssTools } from './components/views/Ops';
import { ViewAccessControl, ViewEndpointSecurity } from './components/views/Security';

// --- NAV ITEM DEFINITION ---
const NAV_MENU = [
  {
    category: "Security Posture",
    items: [
      { id: 'EXEC_SUMMARY', label: "Executive Summary", icon: LayoutDashboard },
      { id: 'SOC_OPS', label: "SOC Operations", icon: Activity }, // Main View
      { id: 'RISK_ANALYSIS', label: "Risk Analysis", icon: AlertOctagon }
    ]
  },
  {
    category: "Infrastructure & IDS",
    items: [
      { id: 'NETWORK_OPS', label: "Network Operations", icon: Router },
      { id: 'IDS_MANAGER', label: "IDS Manager", icon: Eye },
    ]
  },
  {
    category: "Incident Review",
    items: [
      { id: 'THREAT_INTEL', label: "Threat Intelligence", icon: Globe },
      { id: 'AUDIT', label: "Audit Dashboards", icon: ClipboardList },
    ]
  },
  {
    category: "GRC & Frameworks",
    items: [
      { id: 'THREAT_MODEL', label: "Threat Modeling (STRIDE/VAST)", icon: Layers },
      { id: 'RISK_GOV', label: "Risk & Privacy (OCTAVE/LINDDUN)", icon: ShieldCheck }
    ]
  },
  {
    category: "Forensics & Scans",
    items: [
      { id: 'VULN_SCANNER', label: "Vulnerability Scanner", icon: Bug },
      { id: 'FORENSICS_LAB', label: "Forensics Lab (L1)", icon: Microscope }
    ]
  },
  {
    category: "Identity & Endpoint",
    items: [
      { id: 'ACCESS', label: "Access Control (IAM)", icon: UserCheck },
      { id: 'ENDPOINT', label: "Endpoint Security", icon: Server },
      { id: 'USER_ACTIVITY', label: "User Activity Logs", icon: Users },
    ]
  },
  {
    category: "Integrations",
    items: [
      { id: 'OSS_TOOLS', label: "Open Source Tools", icon: Wrench },
    ]
  }
];

const App: React.FC = () => {
  // Application State
  const [isRunning, setIsRunning] = useState(false);
  const [logs, setLogs] = useState<string[]>(["[SYSTEM] S.H.I.E.L.D. Initialized.", "[SYSTEM] Connected Sources: Gmail, AWS CloudTrail, CrowdStrike, Splunk."]);
  const [currentEmail, setCurrentEmail] = useState<EmailData | null>(null);
  const [currentAgent, setCurrentAgent] = useState<'IDLE' | 'SENTINEL' | 'COGNITIVE' | 'PARALLEL' | 'MEMORY'>('IDLE');
  const [currentAnalysis, setCurrentAnalysis] = useState<ThreatAnalysis | undefined>(undefined);
  
  const [scanHistory, setScanHistory] = useState<ScanResult[]>([]);
  const [userActivityLogs, setUserActivityLogs] = useState<LogEntry[]>([]);
  const [threatLevel, setThreatLevel] = useState<SecurityStatus>(SecurityStatus.SECURE);
  
  // Dashboard Metrics
  const [blockedCount, setBlockedCount] = useState(0);
  const [scannedCount, setScannedCount] = useState(0);
  const [activeUsers, setActiveUsers] = useState(12);

  // Navigation State
  const [activeView, setActiveView] = useState('SOC_OPS');
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  // Human in the Loop State
  const [pendingReview, setPendingReview] = useState<{email: EmailData, analysis: ThreatAnalysis} | null>(null);

  // Gmail State
  const [dataSource, setDataSource] = useState<'MOCK' | 'GMAIL'>('MOCK');
  const [gmailToken, setGmailToken] = useState('');
  const [showSettings, setShowSettings] = useState(false);
  const processedGmailIds = useRef<Set<string>>(new Set());

  // Refs for simulation loop
  const processingRef = useRef(false);

  // Add a log line to terminal
  const addLog = (msg: string) => {
    const time = new Date().toLocaleTimeString([], { hour12: false });
    setLogs(prev => [...prev.slice(-49), `[${time}] ${msg}`]);
  };

  const toggleSystem = () => {
    if (!isRunning && dataSource === 'GMAIL' && !gmailToken) {
      addLog("[SYSTEM] ❌ Cannot activate: Gmail Access Token required.");
      setShowSettings(true);
      return;
    }
    setIsRunning(!isRunning);
  };

  const fetchNextEmail = async (): Promise<EmailData | null> => {
    if (dataSource === 'MOCK') {
      return generateMockEmail();
    } else {
      if (!gmailToken) {
        addLog("[ERROR] Gmail Token missing. Reverting to Simulation.");
        setDataSource('MOCK');
        return generateMockEmail();
      }
      try {
        const tool = new GmailTool(gmailToken);
        const latestIds = await tool.listLatestMessages(5);
        const newId = latestIds.find(id => !processedGmailIds.current.has(id));
        if (newId) {
          addLog(`[GMAIL] Fetching content for ID: ${newId.substring(0, 6)}...`);
          const email = await tool.getEmailDetails(newId);
          processedGmailIds.current.add(newId);
          return email;
        } else {
          return null;
        }
      } catch (err: any) {
        addLog(`[ERROR] Gmail API: ${err.message}`);
        if (err.message.includes('401')) {
           setIsRunning(false);
           setShowSettings(true);
           addLog("[SYSTEM] ⚠️ Token Expired. Please refresh token.");
        }
        return null;
      }
    }
  };

  const handleHumanDecision = (decision: 'ALLOW' | 'BLOCK') => {
    if (!pendingReview) return;
    const { email, analysis } = pendingReview;
    let action: ScanResult['actionTaken'] = 'MANUAL_ALLOW';
    let logMsg = "";
    if (decision === 'BLOCK') {
        action = 'MANUAL_BLOCK';
        logMsg = `🔴 THREAT CONFIRMED BY OPERATOR. BLOCKED.`;
        setBlockedCount(prev => prev + 1);
        setThreatLevel(SecurityStatus.ELEVATED);
        MemoryBank.addToMemory(email.sender, 'SENDER', 'BAD', 'Manual Block by Operator');
    } else {
        action = 'MANUAL_ALLOW';
        logMsg = `🟢 FALSE POSITIVE CLEARED BY OPERATOR. RELEASED.`;
        setThreatLevel(SecurityStatus.SECURE);
        MemoryBank.addToMemory(email.sender, 'SENDER', 'GOOD', 'Manual Allow by Operator');
    }
    addLog(logMsg);
    const result: ScanResult = {
        id: email.id,
        email,
        phishingAnalysis: analysis,
        malwareVerdict: 'clean',
        actionTaken: action,
        timestamp: new Date().toLocaleTimeString()
    };
    setScanHistory(prev => [result, ...prev].slice(0, 50));
    setPendingReview(null);
    processingRef.current = false;
  };

  const runAgentPipeline = async () => {
    if (processingRef.current || pendingReview) return;
    processingRef.current = true;
    if (Math.random() > 0.6) addLog(generateInfrastructureLog());

    const email = await fetchNextEmail();
    if (!email) {
      if (dataSource === 'GMAIL') addLog("[GMAIL] No new emails. Standing by...");
      processingRef.current = false;
      return;
    }

    const userLog = generateMockLog("alice");
    setUserActivityLogs(prev => [userLog, ...prev].slice(0, 50));
    setCurrentEmail(email);
    setCurrentAnalysis(undefined);
    setScannedCount(prev => prev + 1);
    addLog(`📨 RECEIVED: ${email.subject.substring(0, 30)}...`);

    setCurrentAgent('SENTINEL');
    await new Promise(r => setTimeout(r, 600));
    let phishResult = runHeuristicScan(email.sender, email.subject, email.body);
    if (phishResult.agentUsed === 'MEMORY_RECALL') {
        setCurrentAgent('MEMORY');
        addLog(`[MEMORY BANK] 🧠 Recall Hit: Known Malicious Sender. Auto-Blocking.`);
        await new Promise(r => setTimeout(r, 1000));
    } else {
        addLog(`[SENTINEL] Preliminary Risk Score: ${phishResult.score}`);
    }

    if (phishResult.agentUsed !== 'MEMORY_RECALL' && (phishResult.score > 20 || Math.random() < 0.1)) {
      addLog(`[SYSTEM] ⚠️ Threshold Exceeded. Escalating to COGNITIVE CORE...`);
      setCurrentAgent('COGNITIVE');
      phishResult = await runCognitiveScan(email);
      if (phishResult.groundingUrls?.length) addLog(`[COGNITIVE] 🔍 Google Search Tool Used. Verified sender reputation.`);
      addLog(`[COGNITIVE] Final Risk Assessment: ${phishResult.score}/100`);
    }
    setCurrentAnalysis(phishResult);

    if (phishResult.score >= 50 && phishResult.score <= 75) {
       addLog(`[SYSTEM] ⚠️ AMBIGUOUS THREAT DETECTED (${phishResult.score}/100). PAUSING FOR HUMAN REVIEW.`);
       setThreatLevel(SecurityStatus.INTERVENTION);
       setPendingReview({ email, analysis: phishResult });
       return; 
    }

    setCurrentAgent('PARALLEL');
    addLog(`[PARALLEL] Forking processes: Malware Sandbox + Insider Threat Agent...`);
    const [malwareResult, anomalies] = await Promise.all([
        checkFileHash(email.attachment_hash, phishResult.score),
        checkInsiderThreats([userLog], "alice")
    ]);
    if (anomalies.length > 0) addLog(`[INSIDER AGENT] 🚨 Anomaly: Large data transfer detected.`);
    if (malwareResult.verdict === 'malicious') addLog(`[MALWARE AGENT] 🦠 Sandbox Alert: ${malwareResult.family}`);

    let action: ScanResult['actionTaken'] = 'SAFE';
    let logMsg = "";
    if (malwareResult.verdict === 'malicious' || (phishResult.is_phishing && anomalies.length > 0)) {
        action = 'LOCK_AND_BLOCK';
        logMsg = `🔴 CRITICAL THREAT: ${malwareResult.family || "APT Detected"}. USER LOCKED.`;
        setBlockedCount(prev => prev + 1);
        setThreatLevel(SecurityStatus.CRITICAL);
        if (malwareResult.verdict === 'malicious') MemoryBank.addToMemory(email.attachment_hash, 'HASH', 'BAD', malwareResult.family);
    } else if (phishResult.is_phishing) {
        action = 'MONITOR';
        logMsg = `🟡 HIGH RISK: ${phishResult.analysis}`;
        setThreatLevel(SecurityStatus.ELEVATED);
    } else {
        logMsg = `🟢 CLEAN: Released to inbox.`;
        setThreatLevel(SecurityStatus.SECURE);
    }
    addLog(logMsg);
    
    const result: ScanResult = {
        id: email.id, email, phishingAnalysis: phishResult, malwareVerdict: malwareResult.verdict as 'clean' | 'malicious',
        actionTaken: action, timestamp: new Date().toLocaleTimeString(), parallelResults: { malware: malwareResult, insider: anomalies }
    };
    setScanHistory(prev => [result, ...prev].slice(0, 50));
    await new Promise(r => setTimeout(r, dataSource === 'GMAIL' ? 5000 : 2000));
    setCurrentAgent('IDLE');
    processingRef.current = false;
  };

  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    if (isRunning) {
      if (!processingRef.current) addLog(dataSource === 'GMAIL' ? "[SYSTEM] Connected to Gmail API via Proxy." : "[SYSTEM] Multi-Agent System Active (Simulation).");
      interval = setInterval(() => { if (!processingRef.current && !pendingReview) runAgentPipeline(); }, 1000); 
    } else {
      processingRef.current = false;
      setCurrentAgent('IDLE');
    }
    return () => clearInterval(interval);
  }, [isRunning, dataSource, gmailToken, pendingReview]);

  const chartData = scanHistory.map(scan => ({ name: scan.timestamp, score: scan.phishingAnalysis.score, verdict: scan.malwareVerdict })).reverse();

  return (
    <div className="flex h-screen bg-slate-950 text-slate-200 font-sans overflow-hidden">
      {/* SETTINGS MODAL */}
      {showSettings && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 p-6 rounded-lg max-w-md w-full shadow-2xl">
            <h3 className="text-xl font-bold mb-4 flex items-center gap-2"><Settings className="w-5 h-5 text-cyan-400"/> System Configuration</h3>
            <div className="mb-6">
              <label className="block text-sm font-medium text-slate-400 mb-2">Data Ingestion Source</label>
              <div className="flex gap-4">
                <button onClick={() => setDataSource('MOCK')} className={`flex-1 py-2 px-4 rounded border ${dataSource === 'MOCK' ? 'bg-cyan-900/50 border-cyan-500 text-cyan-400' : 'bg-slate-800 border-slate-700 text-slate-500'}`}>Simulation</button>
                <button onClick={() => setDataSource('GMAIL')} className={`flex-1 py-2 px-4 rounded border ${dataSource === 'GMAIL' ? 'bg-cyan-900/50 border-cyan-500 text-cyan-400' : 'bg-slate-800 border-slate-700 text-slate-500'}`}>Gmail Live API</button>
              </div>
            </div>
            {dataSource === 'GMAIL' && (
              <div className="mb-6 animate-in fade-in slide-in-from-top-4">
                <label className="block text-sm font-medium text-slate-400 mb-2">OAuth Access Token</label>
                <input type="password" value={gmailToken} onChange={(e) => setGmailToken(e.target.value)} placeholder="Paste token..." className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs font-mono text-slate-300 focus:border-cyan-500 outline-none"/>
                <div className="mt-3 bg-slate-800/50 p-3 rounded text-[10px] text-slate-400 border border-slate-700">
                  <a href="https://developers.google.com/oauthplayground/" target="_blank" rel="noreferrer" className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-bold">Open OAuth Playground <ExternalLink className="w-3 h-3" /></a>
                </div>
              </div>
            )}
            <div className="flex justify-end"><button onClick={() => setShowSettings(false)} className="bg-slate-100 hover:bg-white text-slate-900 font-bold py-2 px-6 rounded transition-colors">Save Configuration</button></div>
          </div>
        </div>
      )}

      {/* SIDEBAR NAVIGATION */}
      <div className={`bg-slate-900 border-r border-slate-800 flex flex-col transition-all duration-300 ${isSidebarOpen ? 'w-64' : 'w-16'}`}>
        <div className="p-4 flex items-center justify-between border-b border-slate-800 h-16">
          {isSidebarOpen ? (<span className="font-bold text-lg tracking-widest text-cyan-400">SHIELD<span className="text-white">OS</span></span>) : (<Shield className="w-8 h-8 text-cyan-400 mx-auto" />)}
          <button onClick={() => setIsSidebarOpen(!isSidebarOpen)} className="text-slate-500 hover:text-white">{isSidebarOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4 mx-auto" />}</button>
        </div>
        <div className="flex-1 overflow-y-auto py-4">
           {NAV_MENU.map((cat, i) => (
             <div key={i} className="mb-6">
               {isSidebarOpen && <h4 className="px-6 mb-2 text-xs font-bold text-slate-600 uppercase tracking-wider">{cat.category}</h4>}
               <ul>
                 {cat.items.map((item) => (
                   <li key={item.id}>
                     <button onClick={() => setActiveView(item.id)} className={`w-full flex items-center gap-3 px-6 py-2 text-sm transition-colors ${activeView === item.id ? 'text-cyan-400 bg-cyan-900/20 border-r-2 border-cyan-400' : 'text-slate-400 hover:text-white hover:bg-slate-800'}`}>
                       <item.icon className="w-4 h-4 min-w-[16px]" />{isSidebarOpen && <span>{item.label}</span>}
                     </button>
                   </li>
                 ))}
               </ul>
             </div>
           ))}
        </div>
      </div>

      {/* MAIN CONTENT AREA */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-16 bg-slate-950 border-b border-slate-800 flex items-center justify-between px-6">
          <div className="flex items-center gap-4">
             <h2 className="text-xl font-bold text-white uppercase tracking-tight">{NAV_MENU.flatMap(c => c.items).find(i => i.id === activeView)?.label || "Dashboard"}</h2>
             {dataSource === 'GMAIL' && <span className="text-[10px] font-mono text-red-400 border border-red-900 bg-red-950/30 px-2 py-0.5 rounded flex items-center gap-1"><Wifi className="w-3 h-3"/> LIVE FEED</span>}
          </div>
          <div className="flex items-center gap-4">
             <button onClick={() => setShowSettings(true)} className={`p-2 rounded transition-colors ${dataSource === 'GMAIL' && !gmailToken ? 'text-red-400 bg-red-900/20 animate-pulse' : 'text-slate-400 hover:text-white hover:bg-slate-800'}`}><Settings className="w-5 h-5" /></button>
             <div className={`px-4 py-1.5 rounded font-bold tracking-wider border text-xs ${threatLevel === SecurityStatus.SECURE ? 'bg-emerald-950 border-emerald-800 text-emerald-400' : threatLevel === SecurityStatus.ELEVATED ? 'bg-yellow-950 border-yellow-800 text-yellow-400' : threatLevel === SecurityStatus.INTERVENTION ? 'bg-orange-950 border-orange-800 text-orange-400 animate-pulse' : 'bg-red-950 border-red-800 text-red-500 animate-pulse'}`}>
                {threatLevel === SecurityStatus.INTERVENTION ? 'HUMAN REVIEW' : threatLevel}
             </div>
             <button onClick={toggleSystem} className={`flex items-center gap-2 px-6 py-2 rounded font-bold transition-all text-xs ${isRunning ? 'bg-red-600 hover:bg-red-700 text-white' : 'bg-cyan-600 hover:bg-cyan-700 text-white'}`}>
                {isRunning ? <><Pause className="w-4 h-4"/> HALT</> : <><Play className="w-4 h-4"/> ACTIVATE</>}
             </button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-6 scrollbar-thin scrollbar-thumb-slate-700">
           {activeView === 'EXEC_SUMMARY' && (
               <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    <StatCard label="Total Events Scanned" value={scannedCount} icon={Mail} color="text-cyan-500" subtext="+12% vs last hour"/>
                    <StatCard label="Threats Blocked" value={blockedCount} icon={Shield} color="text-red-500" subtext="Autonomously mitigated"/>
                    <StatCard label="Active Agents" value={activeUsers} icon={Users} color="text-purple-500" subtext="Sentinel + Cognitive Core"/>
                    <StatCard label="System Status" value={threatLevel} icon={Activity} color={threatLevel === SecurityStatus.SECURE ? 'text-emerald-500' : 'text-yellow-500'} subtext="Real-time Health"/>
                  </div>
                  {/* Executive Charts */}
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <div className="col-span-2 bg-slate-900 border border-slate-800 rounded-lg p-6">
                        <h3 className="text-sm font-bold text-slate-400 mb-4">THREAT LANDSCAPE TRENDS</h3>
                        <div className="h-64"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chartData}><CartesianGrid strokeDasharray="3 3" stroke="#1e293b"/><XAxis dataKey="name" tick={false} /><YAxis stroke="#475569" /><Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155' }}/><Area type="monotone" dataKey="score" stroke="#ef4444" fillOpacity={1} fill="#ef4444" /></AreaChart></ResponsiveContainer></div>
                    </div>
                    <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 flex flex-col items-center justify-center">
                        <h3 className="text-sm font-bold text-slate-400 mb-4">COMPLIANCE SCORE</h3>
                        <div className="w-40 h-40 flex items-center justify-center bg-slate-950 rounded-full border-4 border-slate-800 shadow-inner">
                             <span className="text-4xl font-bold text-emerald-500">98%</span>
                        </div>
                    </div>
                  </div>
               </div>
           )}

           {activeView === 'SOC_OPS' && (
             <div className="grid grid-cols-12 gap-6 animate-in fade-in slide-in-from-bottom-4">
                <div className="col-span-12 lg:col-span-8 space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <StatCard label="Threats Neutralized" value={blockedCount} icon={Lock} color="text-red-500" subtext="Last 24 Hours"/>
                        <StatCard label="Cognitive Scans" value={scannedCount} icon={Activity} color="text-purple-500" subtext="LLM Inferences"/>
                        <StatCard label="Response Time" value="1.2s" icon={RefreshCw} color="text-cyan-500" subtext="Avg. Mitigation Speed"/>
                    </div>
                    <div className="grid grid-cols-1 gap-6">
                        <div className="col-span-1">
                            <h2 className="text-sm font-bold text-slate-400 mb-3 flex items-center gap-2"><RefreshCw className={`w-4 h-4 ${isRunning && !pendingReview ? 'animate-spin' : ''}`}/> LIVE AGENT MONITOR</h2>
                            <ScannerVisual currentEmail={currentEmail} scanning={currentAgent !== 'IDLE'} currentAgent={currentAgent} analysis={currentAnalysis} isPendingReview={!!pendingReview} onHumanDecision={handleHumanDecision}/>
                        </div>
                        <div className="col-span-1 h-64">
                            <h2 className="text-sm font-bold text-slate-400 mb-3">RISK VELOCITY</h2>
                            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 h-full">
                                <ResponsiveContainer width="100%" height="100%"><BarChart data={chartData}><Bar dataKey="score" radius={[4, 4, 0, 0]}>{chartData.map((entry, index) => (<Cell key={`cell-${index}`} fill={entry.score > 50 ? '#ef4444' : '#22d3ee'} />))}</Bar></BarChart></ResponsiveContainer>
                            </div>
                        </div>
                    </div>
                    <div><h2 className="text-sm font-bold text-slate-400 mb-3">SYSTEM LOGS</h2><Terminal logs={logs} /></div>
                </div>
                <div className="col-span-12 lg:col-span-4 flex flex-col h-full">
                     <div className="flex items-center justify-between mb-3"><h2 className="text-sm font-bold text-slate-400">RECENT DECISIONS</h2></div>
                     <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden flex-1 max-h-[1000px] overflow-y-auto">
                        <div className="scrollbar-thin scrollbar-thumb-slate-700">
                            {scanHistory.map((scan) => (
                                <div key={scan.id} className="p-4 border-b border-slate-800 hover:bg-slate-800/50 transition-colors">
                                    <div className="flex justify-between items-start mb-1">
                                        <span className="text-xs font-mono text-slate-500">{scan.timestamp}</span>
                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${scan.actionTaken === 'LOCK_AND_BLOCK' || scan.actionTaken === 'MANUAL_BLOCK' ? 'bg-red-950 text-red-500 border-red-900' : 'bg-emerald-950 text-emerald-500 border-emerald-900'}`}>{scan.actionTaken}</span>
                                    </div>
                                    <h4 className="font-semibold text-sm text-slate-200 truncate">{scan.email.subject}</h4>
                                </div>
                            ))}
                        </div>
                     </div>
                </div>
             </div>
           )}

           {/* INFRASTRUCTURE VIEWS */}
           {activeView === 'NETWORK_OPS' && <ViewNetworkOps addLog={addLog} />}
           {activeView === 'IDS_MANAGER' && <ViewIDSManager />}
           
           {/* FORENSICS VIEWS */}
           {activeView === 'VULN_SCANNER' && <ViewVulnerabilityScanner />}
           {activeView === 'FORENSICS_LAB' && <ViewForensicsLab />}
           
           {/* GOVERNANCE VIEWS */}
           {activeView === 'THREAT_MODEL' && <ViewThreatModeling />}
           {activeView === 'RISK_GOV' && <ViewRiskGovernance />}
           {activeView === 'RISK_ANALYSIS' && <ViewRiskAnalysis threatLevel={threatLevel} />}

           {/* OPS & INTEL VIEWS (NEW) */}
           {activeView === 'THREAT_INTEL' && <ViewThreatIntel scanHistory={scanHistory} />}
           {activeView === 'AUDIT' && <ViewAudit />}
           {activeView === 'USER_ACTIVITY' && <ViewUserActivity logs={userActivityLogs} />}
           {activeView === 'OSS_TOOLS' && <ViewOssTools />}

           {/* SECURITY & IDENTITY VIEWS (NEW) */}
           {activeView === 'ACCESS' && <ViewAccessControl />}
           {activeView === 'ENDPOINT' && <ViewEndpointSecurity />}
        </div>
      </div>
    </div>
  );
};

export default App;
