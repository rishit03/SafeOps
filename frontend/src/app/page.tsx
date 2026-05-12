// // "use client";

// // import { useEffect, useState } from "react";
// // import { toast } from "sonner";
// // import { motion } from "framer-motion";
// // import {
// //   Activity,
// //   AlertTriangle,
// //   CheckCircle2,
// //   ShieldCheck,
// //   Sparkles,
// //   Zap,
// // } from "lucide-react";
// // import {
// //   LineChart,
// //   Line,
// //   XAxis,
// //   YAxis,
// //   Tooltip,
// //   ResponsiveContainer,
// // } from "recharts";

// // type Finding = {
// //   id: number;
// //   fingerprint: string;
// //   title: string;
// //   severity: string;
// //   remediation_priority?: string;
// //   raw?: {
// //     why_it_matters?: string;
// //     [key: string]: any;
// //   };
// // };

// // type Scan = {
// //   id: number;
// //   profile: string;
// //   risk_score: number;
// //   risk_level: string;
// //   findings: Finding[];
// // };

// // type ActivityItem = {
// //   id: number;
// //   action: string;
// //   details: string;
// //   created_at?: string;
// // };

// // type ScanHistoryItem = {
// //   id: number;
// //   risk_score: number;
// //   risk_level: string;
// //   created_at: string;
// // };

// // type FixHistoryItem = {
// //   id: number;
// //   issue_id: string;
// //   title: string;
// //   severity: string;
// //   status: string;
// //   message: string;
// //   before_risk_score: number;
// //   after_risk_score: number;
// //   created_at?: string;
// // };

// // const formatUserDateTime = (value?: string) => {
// //   if (!value) return "Not available";

// //   const utcValue = value.endsWith("Z") ? value : `${value}Z`;

// //   return new Date(utcValue).toLocaleString(undefined, {
// //     year: "numeric",
// //     month: "short",
// //     day: "numeric",
// //     hour: "2-digit",
// //     minute: "2-digit",
// //   });
// // };

// // export default function Home() {
// //   const [scan, setScan] = useState<Scan | null>(null);
// //   const [fixing, setFixing] = useState(false);
// //   const [scanning, setScanning] = useState(false);
// //   const [activity, setActivity] = useState<ActivityItem[]>([]);
// //   const [history, setHistory] = useState<ScanHistoryItem[]>([]);
// //   const [settings, setSettings] = useState<any>(null);
// //   const [fixHistory, setFixHistory] = useState<FixHistoryItem[]>([]);
// //   const [saving, setSaving] = useState(false);

// //   const fetchScan = async () => {
// //     try {
// //       const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/scans/latest`);
// //       const data = await res.json();
// //       setScan(data);
// //     } catch {
// //       setScan(null);
// //     }
// //   };

// //   const fetchActivity = async () => {
// //     try {
// //       const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/activity`);
// //       const data = await res.json();
// //       setActivity(data);
// //     } catch {
// //       setActivity([]);
// //     }
// //   };

// //   const fetchHistory = async () => {
// //     try {
// //       const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/scans/history`);
// //       const data = await res.json();
// //       setHistory(data);
// //     } catch {
// //       setHistory([]);
// //     }
// //   };

// //   const fetchFixHistory = async () => {
// //     try {
// //       const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/fix-history`);
// //       const data = await res.json();
// //       setFixHistory(data);
// //     } catch {
// //       setFixHistory([]);
// //     }
// //   };

// //   const fetchSettings = async () => {
// //     const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/settings`);
// //     const data = await res.json();
// //     setSettings(data);
// //   };

// //   const refreshDashboard = async () => {
// //     await fetchScan();
// //     await fetchActivity();
// //     await fetchHistory();
// //     await fetchSettings();
// //     await fetchFixHistory();
// //   };

// //   useEffect(() => {
// //     refreshDashboard();
// //   }, []);

// //   const runScan = async () => {
// //     setScanning(true);

// //     try {
// //       const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/scan/run`, {
// //         method: "POST",
// //       });

// //       const data = await res.json();

// //       if (!res.ok) {
// //         toast.error(data.detail || "Scan failed. Check backend logs.");
// //         return;
// //       }

// //       toast.success(data.message || "Scan completed");
// //       if (!settings?.slack_webhook_url) {
// //         toast("Add Slack webhook to receive alerts");
// //       }

// //       setTimeout(() => {
// //         refreshDashboard();
// //       }, 1500);
// //     } catch {
// //       toast.error("Scan failed");
// //     } finally {
// //       setScanning(false);
// //     }
// //   };

// //   if (!scan) {
// //     return (
// //       <div className="h-screen flex items-center justify-center bg-black text-white">
// //         <div className="text-center max-w-md">
// //           <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-blue-500/20 text-blue-400">
// //             <ShieldCheck size={24} />
// //           </div>

// //           <h1 className="text-3xl font-bold">SafeOps</h1>

// //           <p className="text-gray-400 mt-2">
// //             No scan data yet. Run your first cloud scan to populate the dashboard.
// //           </p>

// //           <button
// //             disabled={scanning}
// //             onClick={runScan}
// //             className={`mt-6 rounded-xl px-5 py-3 text-sm font-semibold transition ${
// //               scanning
// //                 ? "bg-gray-700 opacity-70 cursor-not-allowed"
// //                 : "bg-blue-500 hover:bg-blue-600 hover:scale-105 active:scale-95"
// //             }`}
// //           >
// //             {scanning ? "Scanning..." : "Run First Scan"}
// //           </button>
// //         </div>
// //       </div>
// //     );
// //   }

// //   const riskColor =
// //     scan.risk_level === "Critical"
// //       ? "text-red-500"
// //       : scan.risk_level === "High"
// //       ? "text-orange-400"
// //       : scan.risk_level === "Moderate"
// //       ? "text-yellow-400"
// //       : "text-green-400";

// //   const isValidSlackWebhook = (url?: string) =>
// //     !!url && url.startsWith("https://hooks.slack.com/services/");

// //   return (
// //     <motion.div
// //       initial={{ opacity: 0 }}
// //       animate={{ opacity: 1 }}
// //       transition={{ duration: 0.35 }}
// //       className="min-h-screen bg-black text-white"
// //     >
// //       {/* SCAN OVERLAY */}
// //       {scanning && (
// //         <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
// //           <motion.div
// //             initial={{ opacity: 0, scale: 0.92 }}
// //             animate={{ opacity: 1, scale: 1 }}
// //             transition={{ duration: 0.2, ease: "easeOut" }}
// //             className="rounded-2xl border border-blue-500/30 bg-gray-950 p-8 shadow-2xl shadow-blue-500/20"
// //           >
// //             <div className="mx-auto mb-5 h-12 w-12 animate-spin rounded-full border-4 border-blue-500/20 border-t-blue-400" />

// //             <h2 className="text-center text-xl font-semibold">
// //               Scanning your AWS account
// //             </h2>

// //             <p className="mt-2 text-center text-sm text-gray-400">
// //               Checking S3, security groups, RDS, and IAM risks...
// //             </p>
// //           </motion.div>
// //         </div>
// //       )}

// //       {/* MAIN CONTENT */}
// //       <div className="mx-auto max-w-7xl px-8 py-12 space-y-6">
// //         <div>
// //           <h1 className="text-3xl font-bold">SafeOps Dashboard</h1>
// //           <p className="text-sm text-gray-500 mt-1">
// //             Real-time AWS security posture and automated remediation
// //           </p>
// //         </div>

// //         {/* Hero / SaaS landing header */}
// //         <div className="relative mb-10 overflow-hidden rounded-3xl border border-gray-800 bg-gradient-to-br from-gray-950 via-gray-900 to-black p-8">
// //           <div className="absolute right-0 top-0 h-64 w-64 rounded-full bg-blue-500/10 blur-3xl" />
// //           <div className="absolute bottom-0 left-20 h-48 w-48 rounded-full bg-green-500/10 blur-3xl" />

// //           <div className="relative flex flex-col gap-8 lg:flex-row lg:items-center lg:justify-between">
// //             <div>
// //               <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-blue-500/30 bg-blue-500/10 px-3 py-1 text-sm text-blue-300">
// //                 <Sparkles size={14} />
// //                 AWS security command center for startups
// //               </div>

// //               <h1 className="max-w-3xl text-5xl font-bold tracking-tight">
// //                 Find, prioritize, and fix cloud risks before they become incidents.
// //               </h1>

// //               <p className="mt-4 max-w-2xl text-gray-400">
// //                 SafeOps turns AWS exposure checks into a live control plane:
// //                 scan your account, understand what matters, and fix high-signal
// //                 issues directly from the dashboard.
// //               </p>

// //               <div className="mt-6 flex flex-wrap gap-3">
// //                 <button
// //                   disabled={scanning}
// //                   onClick={runScan}
// //                   className={`rounded-xl px-5 py-3 text-sm font-semibold transition ${
// //                     scanning
// //                       ? "bg-gray-700 opacity-70 cursor-not-allowed"
// //                       : "bg-blue-500 hover:bg-blue-600 hover:scale-105 active:scale-95 shadow-lg shadow-blue-500/20"
// //                   }`}
// //                 >
// //                   {scanning ? "Scanning..." : "Run Scan"}
// //                 </button>

// //                 <button className="rounded-xl border border-gray-700 px-5 py-3 text-sm font-semibold text-gray-300 hover:border-gray-500 hover:text-white transition">
// //                   View Activity
// //                 </button>
// //               </div>
// //             </div>

// //             <div className="rounded-2xl border border-gray-800 bg-black/40 p-5 shadow-2xl">
// //               <div className="mb-3 flex items-center gap-2 text-sm text-gray-400">
// //                 <Zap size={16} className="text-yellow-400" />
// //                 Current posture
// //               </div>

// //               <div className="text-5xl font-bold">{scan.risk_score}/100</div>
// //               <div className={`mt-2 text-lg font-semibold ${riskColor}`}>
// //                 {scan.risk_level}
// //               </div>

// //               <div className="mt-4 text-sm text-gray-400">
// //                 {scan.findings.length} active finding
// //                 {scan.findings.length === 1 ? "" : "s"}
// //               </div>
// //               {history.length > 0 && (
// //                 <div className="mt-2 text-xs text-gray-400">
// //                   Last scan:{" "}
// //                   {formatUserDateTime(history[history.length - 1]?.created_at)}
// //                 </div>
// //               )}
// //             </div>
// //           </div>
// //         </div>

// //         <div className="bg-gray-900 p-6 rounded-xl">
// //           <h2 className="text-xl font-semibold mb-4">Settings</h2>

// //           {!settings ? (
// //             <p className="text-gray-500">Loading settings...</p>
// //           ) : (
// //             <div className="space-y-4">
// //               <div>
// //                 <label className="text-sm text-gray-400">AWS Region</label>
// //                 <input
// //                   value={settings?.aws_region || ""}
// //                   onChange={(e) =>
// //                     setSettings({ ...settings, aws_region: e.target.value })
// //                   }
// //                   className="w-full mt-1 p-2 rounded bg-black border border-gray-700"
// //                 />
// //               </div>

// //               <div>
// //                 <label className="text-sm text-gray-400">Role ARN (optional)</label>
// //                 <input
// //                   value={settings?.role_arn || ""}
// //                   onChange={(e) =>
// //                     setSettings({ ...settings, role_arn: e.target.value })
// //                   }
// //                   className="w-full mt-1 p-2 rounded bg-black border border-gray-700"
// //                 />
// //               </div>

// //               <div>
// //                 <label className="text-sm text-gray-400">Slack Webhook URL</label>
// //                 <input
// //                   value={settings?.slack_webhook_url || ""}
// //                   onChange={(e) =>
// //                     setSettings({ ...settings, slack_webhook_url: e.target.value })
// //                   }
// //                   placeholder="https://hooks.slack.com/services/..."
// //                   className="w-full mt-1 p-2 rounded bg-black border border-gray-700"
// //                 />
// //               </div>

// //               {isValidSlackWebhook(settings?.slack_webhook_url) ? (
// //                 <p className="text-green-400 text-sm mt-1">
// //                   Slack alerts enabled
// //                 </p>
// //               ) : settings?.slack_webhook_url ? (
// //                 <p className="text-red-400 text-sm mt-1">
// //                   Invalid Slack webhook URL
// //                 </p>
// //               ) : (
// //                 <p className="text-yellow-400 text-sm mt-1">
// //                   No Slack webhook configured
// //                 </p>
// //               )}

// //               <div className="flex gap-3">
// //                 <button
// //                   disabled={saving}
// //                   onClick={async () => {
// //                     setSaving(true);

// //                     try {
// //                       const res = await fetch(
// //                         `${process.env.NEXT_PUBLIC_API_URL}/api/settings`,
// //                         {
// //                           method: "POST",
// //                           headers: { "Content-Type": "application/json" },
// //                           body: JSON.stringify(settings),
// //                         }
// //                       );

// //                       const data = await res.json();

// //                       if (!res.ok) {
// //                         toast.error(data.detail || "Failed to update settings");
// //                         return;
// //                       }

// //                       toast.success(data.message || "Settings saved");
// //                     } catch {
// //                       toast.error("Settings update failed");
// //                     } finally {
// //                       setSaving(false);
// //                     }
// //                   }}
// //                   className={`px-4 py-2 rounded ${
// //                     saving ? "bg-gray-700" : "bg-blue-500 hover:bg-blue-600"
// //                   }`}
// //                 >
// //                   {saving ? "Saving..." : "Save"}
// //                 </button>

// //                 <button
// //                   onClick={async () => {
// //                     const res = await fetch(
// //                       `${process.env.NEXT_PUBLIC_API_URL}/api/settings/test-aws`,
// //                       { method: "POST" }
// //                     );
// //                     const data = await res.json();

// //                     if (data.success) {
// //                       toast.success(`Connected: ${data.account_id}`);
// //                     } else {
// //                       toast.error(data.message);
// //                     }
// //                   }}
// //                   className="bg-green-500 px-4 py-2 rounded"
// //                 >
// //                   Test Connection
// //                 </button>
// //               </div>
// //             </div>
// //           )}
// //         </div>

// //         {/* Metrics */}
// //         <div className="mb-8 grid grid-cols-1 gap-6 md:grid-cols-3">
// //           <motion.div
// //             initial={{ opacity: 0, y: 18 }}
// //             animate={{ opacity: 1, y: 0 }}
// //             transition={{ duration: 0.4 }}
// //             className="rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-xl"
// //           >
// //             <p className="flex items-center gap-2 text-sm text-gray-400">
// //               <ShieldCheck size={16} />
// //               Risk Score
// //             </p>
// //             <p className="mt-3 text-4xl font-bold">{scan.risk_score}/100</p>
// //             <p className="mt-2 text-sm text-gray-500">
// //               Lower is better. Updated from latest scan.
// //             </p>
// //           </motion.div>

// //           <motion.div
// //             initial={{ opacity: 0, y: 18 }}
// //             animate={{ opacity: 1, y: 0 }}
// //             transition={{ duration: 0.45 }}
// //             className="rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-xl"
// //           >
// //             <p className="flex items-center gap-2 text-sm text-gray-400">
// //               <AlertTriangle size={16} />
// //               Risk Level
// //             </p>
// //             <p className={`mt-3 text-4xl font-bold ${riskColor}`}>
// //               {scan.risk_level}
// //             </p>
// //             <p className="mt-2 text-sm text-gray-500">
// //               Based on active high-signal findings.
// //             </p>
// //           </motion.div>

// //           <motion.div
// //             initial={{ opacity: 0, y: 18 }}
// //             animate={{ opacity: 1, y: 0 }}
// //             transition={{ duration: 0.5 }}
// //             className="rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-xl"
// //           >
// //             <p className="flex items-center gap-2 text-sm text-gray-400">
// //               <Activity size={16} />
// //               Active Findings
// //             </p>
// //             <p className="mt-3 text-4xl font-bold">{scan.findings.length}</p>
// //             <p className="mt-2 text-sm text-gray-500">
// //               Issues requiring review or action.
// //             </p>
// //           </motion.div>
// //         </div>

// //         {/* Primary Action */}
// //         {scan.findings.length > 0 && (
// //           <motion.div
// //             initial={{ opacity: 0, y: 12 }}
// //             animate={{ opacity: 1, y: 0 }}
// //             transition={{ duration: 0.35 }}
// //             className="mb-6 flex items-center justify-between rounded-2xl border border-blue-500/20 bg-blue-500/10 p-5"
// //           >
// //             <div>
// //               <p className="font-semibold text-blue-200">
// //                 One-click hardening available
// //               </p>
// //               <p className="text-sm text-gray-400">
// //                 Apply all supported high-signal fixes, then refresh posture automatically.
// //               </p>
// //             </div>

// //             <button
// //               disabled={fixing}
// //               className={`rounded-xl px-5 py-3 text-sm font-semibold transition ${
// //                 fixing
// //                   ? "bg-gray-700 opacity-70 cursor-not-allowed"
// //                   : "bg-blue-500 hover:bg-blue-600 hover:scale-105 active:scale-95 shadow-lg shadow-blue-500/20"
// //               }`}
// //               onClick={async () => {
// //                 const confirmFix = confirm(
// //                   "This will fix all high-signal issues. Continue?"
// //                 );
// //                 if (!confirmFix) return;

// //                 setFixing(true);

// //                 try {
// //                   const res = await fetch(
// //                     `${process.env.NEXT_PUBLIC_API_URL}/api/fix`,
// //                     {
// //                       method: "POST",
// //                       headers: {
// //                         "Content-Type": "application/json",
// //                       },
// //                       body: JSON.stringify({
// //                         all_critical: true,
// //                       }),
// //                     }
// //                   );

// //                   const data = await res.json();

// //                   if (!res.ok) {
// //                     toast.error(
// //                       data.detail?.includes("already")
// //                         ? "Issue already resolved. Refreshing state."
// //                         : data.detail || "Action failed"
// //                     );
// //                     setFixing(false);
// //                     return;
// //                   }

// //                   toast.success(data.message || "Fixes applied");

// //                   setTimeout(() => {
// //                     refreshDashboard();
// //                     setFixing(false);
// //                   }, 1500);
// //                 } catch {
// //                   toast.error("Fix All failed");
// //                   setFixing(false);
// //                 }
// //               }}
// //             >
// //               {fixing ? "Fixing..." : "Fix All High-Signal"}
// //             </button>
// //           </motion.div>
// //         )}

// //         {/* Top Risk */}
// //         {scan.findings.length > 0 && (
// //           <motion.div
// //             initial={{ opacity: 0, y: 15 }}
// //             animate={{ opacity: 1, y: 0 }}
// //             transition={{ duration: 0.35 }}
// //             className="relative mb-6 overflow-hidden rounded-2xl border border-red-500/50 bg-gradient-to-br from-red-950/40 via-gray-950 to-gray-950 p-6 shadow-2xl shadow-red-950/20"
// //           >
// //             <div className="absolute inset-0 bg-red-500/5 blur-2xl pointer-events-none" />

// //             <div className="relative flex items-center justify-between gap-6">
// //               <div>
// //                 <div className="mb-3 flex items-center gap-2 text-red-400">
// //                   <AlertTriangle size={18} />
// //                   <h2 className="text-xl font-semibold">Top Risk</h2>
// //                 </div>

// //                 <p className="text-lg font-semibold">
// //                   {scan.findings[0].title}
// //                 </p>

// //                 <p className="mt-2 max-w-xl text-sm text-gray-400">
// //                   {scan.findings[0].raw?.why_it_matters ??
// //                     "This misconfiguration may expose your infrastructure to attackers."}
// //                 </p>

// //                 <div className="mt-3 flex flex-wrap gap-2">
// //                   <span
// //                     className={`rounded-full px-3 py-1 text-xs font-semibold ${
// //                       scan.findings[0].severity === "critical"
// //                         ? "bg-red-500/20 text-red-300"
// //                         : scan.findings[0].severity === "high"
// //                         ? "bg-orange-500/20 text-orange-300"
// //                         : "bg-gray-700 text-gray-300"
// //                     }`}
// //                   >
// //                     {scan.findings[0].severity.toUpperCase()}
// //                   </span>

// //                   <span className="rounded-full bg-gray-800 px-3 py-1 text-xs text-gray-300">
// //                     {scan.findings[0].remediation_priority || "Review"}
// //                   </span>
// //                 </div>
// //               </div>

// //               <button
// //                 disabled={fixing}
// //                 onClick={async () => {
// //                   setFixing(true);

// //                   try {
// //                     const res = await fetch(
// //                       `${process.env.NEXT_PUBLIC_API_URL}/api/fix`,
// //                       {
// //                         method: "POST",
// //                         headers: {
// //                           "Content-Type": "application/json",
// //                         },
// //                         body: JSON.stringify({
// //                           issue_id: scan.findings[0].fingerprint,
// //                         }),
// //                       }
// //                     );

// //                     const data = await res.json();

// //                     if (!res.ok) {
// //                       toast.error(
// //                         data.detail?.includes("already")
// //                           ? "Issue already resolved. Refreshing state."
// //                           : data.detail || "Action failed"
// //                       );
// //                       setFixing(false);
// //                       return;
// //                     }

// //                     toast.success(data.message || "Fix applied");

// //                     setTimeout(() => {
// //                       refreshDashboard();
// //                       setFixing(false);
// //                     }, 1500);
// //                   } catch {
// //                     toast.error("Fix failed");
// //                     setFixing(false);
// //                   }
// //                 }}
// //                 className={`rounded-xl px-5 py-3 text-sm font-semibold transition ${
// //                   fixing
// //                     ? "bg-gray-700 opacity-70 cursor-not-allowed"
// //                     : "bg-red-500 hover:bg-red-600 hover:scale-105 active:scale-95 shadow-lg shadow-red-500/20"
// //                 }`}
// //               >
// //                 {fixing ? "Fixing..." : "Fix Now"}
// //               </button>
// //             </div>
// //           </motion.div>
// //         )}

// //         <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
// //           {/* Findings Section */}
// //           <motion.div
// //             initial={{ opacity: 0, y: 18 }}
// //             animate={{ opacity: 1, y: 0 }}
// //             transition={{ duration: 0.45 }}
// //             className="rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-xl"
// //           >
// //             <h2 className="mb-4 text-xl font-semibold">Findings</h2>

// //             {scan.findings.length === 0 ? (
// //               <div className="flex items-start gap-3 rounded-xl border border-green-500/20 bg-green-500/10 p-4">
// //                 <CheckCircle2 className="mt-1 text-green-400" size={22} />
// //                 <div>
// //                   <p className="text-green-400 text-lg font-medium">
// //                     Your cloud is secure
// //                   </p>
// //                   <p className="mt-1 text-sm text-gray-400">
// //                     No high-risk issues detected in the latest scan.
// //                   </p>
// //                   <p className="mt-2 text-xs text-gray-500">
// //                     Run periodic scans to ensure continuous protection.
// //                   </p>
// //                 </div>
// //               </div>
// //             ) : (
// //               <motion.ul
// //                 initial="hidden"
// //                 animate="visible"
// //                 variants={{
// //                   hidden: {},
// //                   visible: {
// //                     transition: {
// //                       staggerChildren: 0.08,
// //                     },
// //                   },
// //                 }}
// //                 className="space-y-4"
// //               >
// //                 {scan.findings.map((f) => (
// //                   <motion.li
// //                     key={f.id}
// //                     variants={{
// //                       hidden: { opacity: 0, y: 10 },
// //                       visible: { opacity: 1, y: 0 },
// //                     }}
// //                     className="rounded-xl border border-gray-800 bg-black/30 p-4 transition hover:border-gray-600"
// //                   >
// //                     <div className="flex items-start justify-between gap-4">
// //                       <div>
// //                         <p className="font-medium">{f.title}</p>
// //                         <span
// //                           className={`mt-2 inline-flex rounded-full px-2 py-1 text-xs font-semibold ${
// //                             f.severity === "critical"
// //                               ? "bg-red-500/20 text-red-400"
// //                               : f.severity === "high"
// //                               ? "bg-orange-500/20 text-orange-400"
// //                               : "bg-gray-700 text-gray-300"
// //                           }`}
// //                         >
// //                           {f.severity.toUpperCase()}
// //                         </span>
// //                       </div>

// //                       <span className="rounded-full bg-gray-800 px-3 py-1 text-xs text-gray-300">
// //                         {f.remediation_priority || "Review"}
// //                       </span>
// //                     </div>
// //                   </motion.li>
// //                 ))}
// //               </motion.ul>
// //             )}
// //           </motion.div>

// //           {/* Activity Section */}
// //           <motion.div
// //             initial={{ opacity: 0, y: 18 }}
// //             animate={{ opacity: 1, y: 0 }}
// //             transition={{ duration: 0.5 }}
// //             className="rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-xl"
// //           >
// //             <h2 className="mb-4 flex items-center gap-2 text-xl font-semibold">
// //               <Activity size={18} />
// //               Activity
// //             </h2>

// //             {activity.length === 0 ? (
// //               <p className="text-gray-500">No activity yet</p>
// //             ) : (
// //               <ul className="space-y-4 text-sm text-gray-400">
// //                 {activity.map((a) => (
// //                   <li
// //                     key={a.id}
// //                     className="flex items-start gap-3 border-l border-gray-800 pl-4"
// //                   >
// //                     <span className="mt-1 h-2 w-2 rounded-full bg-blue-400 shadow-lg shadow-blue-400/40" />
// //                     <div>
// //                       <p className="font-medium text-white">
// //                         <span className="capitalize">{a.action}</span>
// //                       </p>
// //                       <p className="text-gray-300">{a.details}</p>
// //                       {a.created_at && (
// //                         <p className="mt-1 text-xs text-gray-600">
// //                           {formatUserDateTime(a.created_at)}
// //                         </p>
// //                       )}
// //                     </div>
// //                   </li>
// //                 ))}
// //               </ul>
// //             )}
// //           </motion.div>
// //         </div>

// //         <motion.div
// //           initial={{ opacity: 0, y: 18 }}
// //           animate={{ opacity: 1, y: 0 }}
// //           transition={{ duration: 0.55 }}
// //           className="rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-xl"
// //         >
// //           <h2 className="mb-4 text-xl font-semibold">Fix History</h2>

// //           {fixHistory.length === 0 ? (
// //             <p className="text-gray-500">No fixes recorded yet</p>
// //           ) : (
// //             <ul className="space-y-4">
// //               {fixHistory.map((fix) => (
// //                 <li
// //                   key={fix.id}
// //                   className="rounded-xl border border-gray-800 bg-black/30 p-4"
// //                 >
// //                   <div className="flex items-start justify-between gap-4">
// //                     <div>
// //                       <p className="font-medium">{fix.title}</p>
// //                       <p className="mt-1 text-sm text-gray-500">{fix.message}</p>
// //                       {fix.created_at && (
// //                         <p className="mt-1 text-xs text-gray-600">
// //                           {formatUserDateTime(fix.created_at)}
// //                         </p>
// //                       )}
// //                     </div>

// //                     <span
// //                       className={`rounded-full px-3 py-1 text-xs font-semibold ${
// //                         fix.status === "success"
// //                           ? "bg-green-500/20 text-green-400"
// //                           : "bg-red-500/20 text-red-400"
// //                       }`}
// //                     >
// //                       {fix.status.toUpperCase()}
// //                     </span>
// //                   </div>

// //                   <div className="mt-3 text-sm text-gray-400">
// //                     Risk: {fix.before_risk_score}/100 → {fix.after_risk_score}/100
// //                   </div>
// //                 </li>
// //               ))}
// //             </ul>
// //           )}
// //         </motion.div>

// //         {/* Risk Trend */}
// //         <motion.div
// //           initial={{ opacity: 0, y: 18 }}
// //           animate={{ opacity: 1, y: 0 }}
// //           transition={{ duration: 0.55 }}
// //           className="mt-6 rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-xl"
// //         >
// //           <h2 className="mb-4 text-xl font-semibold">Risk Trend</h2>

// //           {history.length === 0 ? (
// //             <p className="text-gray-500">No history yet</p>
// //           ) : (
// //             <div className="h-72">
// //               <ResponsiveContainer width="100%" height="100%">
// //                 <LineChart data={history}>
// //                   <XAxis
// //                     dataKey="created_at"
// //                     tick={{ fill: "#9CA3AF", fontSize: 10 }}
// //                     tickFormatter={(v) =>
// //                       new Date(v.endsWith("Z") ? v : `${v}Z`).toLocaleTimeString(undefined, {
// //                         hour: "2-digit",
// //                         minute: "2-digit",
// //                       })
// //                     }
// //                   />
// //                   <YAxis tick={{ fill: "#9CA3AF", fontSize: 10 }} />
// //                   <Tooltip
// //                     contentStyle={{
// //                       backgroundColor: "#030712",
// //                       border: "1px solid #374151",
// //                       borderRadius: "12px",
// //                       color: "#fff",
// //                     }}
// //                   />
// //                   <Line
// //                     type="monotone"
// //                     dataKey="risk_score"
// //                     stroke="#3B82F6"
// //                     strokeWidth={3}
// //                     dot={{ r: 3 }}
// //                     activeDot={{ r: 5 }}
// //                   />
// //                 </LineChart>
// //               </ResponsiveContainer>
// //             </div>
// //           )}
// //         </motion.div>
// //       </div>
// //     </motion.div>
// //   );
// // }


// //v2

// "use client";

// /*
// SafeOps Swiss Cybernetics UI direction: disciplined graphite command-center surfaces, cobalt action states, amber risk markers,
// IBM Plex typography, asymmetric cockpit layout, and measured instrumentation-style motion. Every component should reinforce
// precision, trust, and operational clarity rather than generic dashboard decoration.
// */

// import { type ReactNode, useCallback, useEffect, useMemo, useState } from "react";
// import { toast } from "sonner";
// import { motion } from "framer-motion";
// import {
//   Activity,
//   AlertCircle,
//   AlertTriangle,
//   ArrowDownRight,
//   CheckCircle2,
//   ChevronRight,
//   Clock3,
//   CloudCog,
//   FileClock,
//   Gauge,
//   History,
//   Loader2,
//   LockKeyhole,
//   RadioTower,
//   RefreshCw,
//   Settings2,
//   ShieldAlert,
//   ShieldCheck,
//   MessageSquare,
//   Sparkles,
//   TerminalSquare,
//   Wand2,
//   Zap,
// } from "lucide-react";
// import {
//   CartesianGrid,
//   Line,
//   LineChart,
//   ResponsiveContainer,
//   Tooltip,
//   XAxis,
//   YAxis,
// } from "recharts";

// type Finding = {
//   id: number;
//   fingerprint: string;
//   title: string;
//   severity: string;
//   remediation_priority?: string;
//   raw?: {
//     why_it_matters?: string;
//     resource?: string;
//     service?: string;
//     fix_priority?: string;
//     can_auto_fix?: boolean;
//     fix_reason?: string;
//     recommended_action?: string;
//     [key: string]: unknown;
//   };
// };

// type Scan = {
//   id: number;
//   profile: string;
//   risk_score: number;
//   risk_level: string;
//   findings: Finding[];
// };

// type ActivityItem = {
//   id: number;
//   action: string;
//   details: string;
//   created_at?: string;
// };

// type ScanHistoryItem = {
//   id: number;
//   risk_score: number;
//   risk_level: string;
//   created_at: string;
// };

// type FixHistoryItem = {
//   id: number;
//   issue_id: string;
//   title: string;
//   severity: string;
//   status: string;
//   message: string;
//   before_risk_score: number;
//   after_risk_score: number;
//   created_at?: string;
// };

// type SafeOpsSettings = {
//   aws_region?: string;
//   role_arn?: string;
//   scan_frequency?: string;
//   slack_webhook_url?: string;
//   [key: string]: unknown;
// };

// type AwsTestResult = {
//   success?: boolean;
//   account_id?: string;
//   message?: string;
//   detail?: string;
// };

// const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "";
// const HERO_IMAGE =
//   "https://d2xsxph8kpxj0f.cloudfront.net/310519663051078584/7QK6F3FEGSF4CiqS29RWd9/safeops-cloud-topology-QZbsZ8T66BEn8xfmBKzuZF.webp";
// const RISK_IMAGE =
//   "https://d2xsxph8kpxj0f.cloudfront.net/310519663051078584/7QK6F3FEGSF4CiqS29RWd9/safeops-risk-meter-QLjiiViS4aDxnBBUt34Ykz.webp";
// const AUDIT_IMAGE =
//   "https://d2xsxph8kpxj0f.cloudfront.net/310519663051078584/7QK6F3FEGSF4CiqS29RWd9/safeops-audit-timeline-WRbxv9PHj8vnG9Y6PjBx4d.webp";

// const highSignalSeverities = new Set(["critical", "high"]);
// const severityRank: Record<string, number> = {
//   critical: 4,
//   high: 3,
//   medium: 2,
//   moderate: 2,
//   low: 1,
// };

// const formatUserDateTime = (value?: string) => {
//   if (!value) return "Not available";

//   const utcValue = value.endsWith("Z") ? value : `${value}Z`;

//   return new Date(utcValue).toLocaleString(undefined, {
//     year: "numeric",
//     month: "short",
//     day: "numeric",
//     hour: "2-digit",
//     minute: "2-digit",
//   });
// };

// const shortTime = (value?: string) => {
//   if (!value) return "—";
//   const utcValue = value.endsWith("Z") ? value : `${value}Z`;
//   return new Date(utcValue).toLocaleTimeString(undefined, {
//     hour: "2-digit",
//     minute: "2-digit",
//   });
// };

// const normalizeSeverity = (value?: string) => (value || "unknown").toLowerCase();

// const riskTone = (riskLevel?: string) => {
//   const level = (riskLevel || "").toLowerCase();
//   if (level.includes("critical")) return "text-red-300 bg-red-500/10 border-red-400/30";
//   if (level.includes("high")) return "text-orange-300 bg-orange-500/10 border-orange-400/30";
//   if (level.includes("moderate") || level.includes("medium")) {
//     return "text-amber-200 bg-amber-500/10 border-amber-300/30";
//   }
//   return "text-emerald-200 bg-emerald-500/10 border-emerald-300/30";
// };

// const severityTone = (severity?: string) => {
//   const normalized = normalizeSeverity(severity);
//   if (normalized === "critical") return "border-red-400/30 bg-red-500/10 text-red-200";
//   if (normalized === "high") return "border-orange-400/30 bg-orange-500/10 text-orange-200";
//   if (normalized === "medium" || normalized === "moderate") {
//     return "border-amber-300/30 bg-amber-500/10 text-amber-100";
//   }
//   return "border-slate-500/30 bg-slate-500/10 text-slate-200";
// };

// const fixPriorityLabel = (priority?: string) => {
//   if (priority === "auto_fix_now") return "Auto-fix available";
//   if (priority === "review_before_fix") return "Review before fix";
//   if (priority === "manual_only") return "Manual only";
//   if (priority === "unsupported") return "Unsupported";
//   return "Review";
// };

// const fixPriorityTone = (priority?: string) => {
//   if (priority === "auto_fix_now") return "border-emerald-300/30 bg-emerald-400/10 text-emerald-200";
//   if (priority === "review_before_fix") return "border-amber-300/30 bg-amber-400/10 text-amber-100";
//   if (priority === "manual_only") return "border-slate-300/20 bg-slate-400/10 text-slate-200";
//   if (priority === "unsupported") return "border-red-300/30 bg-red-400/10 text-red-200";
//   return "border-white/10 bg-white/5 text-slate-300";
// };

// const canShowFixButton = (finding: Finding) => {
//   return finding.raw?.can_auto_fix === true;
// };

// const isValidSlackWebhook = (url?: string) =>
//   !!url && url.startsWith("https://hooks.slack.com/services/");

// async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
//   const response = await fetch(`${API_BASE}${path}`, {
//     ...init,
//     headers: {
//       ...(init?.body ? { "Content-Type": "application/json" } : {}),
//       ...init?.headers,
//     },
//   });

//   let payload: unknown = null;
//   try {
//     payload = await response.json();
//   } catch {
//     payload = null;
//   }

//   if (!response.ok) {
//     const detail =
//       payload && typeof payload === "object" && "detail" in payload
//         ? String((payload as { detail?: unknown }).detail)
//         : `Request failed with status ${response.status}`;
//     throw new Error(detail);
//   }

//   return payload as T;
// }

// function MetricCard({
//   icon: Icon,
//   label,
//   value,
//   detail,
//   tone = "cobalt",
// }: {
//   icon: typeof ShieldCheck;
//   label: string;
//   value: string | number;
//   detail: string;
//   tone?: "cobalt" | "amber" | "green" | "red";
// }) {
//   const tones = {
//     cobalt: "from-cyan-400/20 to-blue-500/5 text-cyan-200",
//     amber: "from-amber-300/20 to-orange-500/5 text-amber-100",
//     green: "from-emerald-300/20 to-emerald-600/5 text-emerald-100",
//     red: "from-red-400/20 to-red-600/5 text-red-100",
//   };

//   return (
//     <motion.article
//       initial={{ opacity: 0, y: 16 }}
//       animate={{ opacity: 1, y: 0 }}
//       transition={{ duration: 0.35 }}
//       className="group relative overflow-hidden rounded-[1.4rem] border border-white/10 bg-slate-950/70 p-5 shadow-2xl shadow-black/20 backdrop-blur"
//     >
//       <div className={`absolute inset-x-0 top-0 h-px bg-gradient-to-r ${tones[tone]}`} />
//       <div className="flex items-start justify-between gap-4">
//         <div>
//           <p className="font-mono text-[0.68rem] uppercase tracking-[0.26em] text-slate-500">{label}</p>
//           <p className="mt-3 text-3xl font-semibold tracking-tight text-white">{value}</p>
//           <p className="mt-2 text-sm leading-6 text-slate-400">{detail}</p>
//         </div>
//         <div className={`rounded-2xl bg-gradient-to-br p-3 ${tones[tone]}`}>
//           <Icon className="h-5 w-5" />
//         </div>
//       </div>
//     </motion.article>
//   );
// }

// function EmptyState({
//   icon: Icon,
//   title,
//   description,
//   action,
// }: {
//   icon: typeof ShieldCheck;
//   title: string;
//   description: string;
//   action?: ReactNode;
// }) {
//   return (
//     <div className="rounded-2xl border border-dashed border-white/12 bg-slate-950/45 p-6 text-center">
//       <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-300/20 bg-cyan-400/10 text-cyan-200">
//         <Icon className="h-5 w-5" />
//       </div>
//       <h3 className="mt-4 text-base font-semibold text-white">{title}</h3>
//       <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-400">{description}</p>
//       {action ? <div className="mt-5">{action}</div> : null}
//     </div>
//   );
// }

// function SectionShell({
//   id,
//   eyebrow,
//   title,
//   description,
//   action,
//   children,
// }: {
//   id?: string;
//   eyebrow: string;
//   title: string;
//   description?: string;
//   action?: ReactNode;
//   children: ReactNode;
// }) {
//   return (
//     <section id={id} className="rounded-[1.6rem] border border-white/10 bg-slate-950/65 p-5 shadow-2xl shadow-black/20 backdrop-blur xl:p-6">
//       <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
//         <div>
//           <p className="font-mono text-[0.68rem] uppercase tracking-[0.28em] text-cyan-300/70">{eyebrow}</p>
//           <h2 className="mt-2 text-xl font-semibold tracking-tight text-white">{title}</h2>
//           {description ? <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-400">{description}</p> : null}
//         </div>
//         {action}
//       </div>
//       {children}
//     </section>
//   );
// }

// export default function Home() {
//   const [scan, setScan] = useState<Scan | null>(null);
//   const [activity, setActivity] = useState<ActivityItem[]>([]);
//   const [history, setHistory] = useState<ScanHistoryItem[]>([]);
//   const [settings, setSettings] = useState<SafeOpsSettings | null>(null);
//   const [fixHistory, setFixHistory] = useState<FixHistoryItem[]>([]);
//   const [initialLoading, setInitialLoading] = useState(true);
//   const [apiError, setApiError] = useState<string | null>(null);
//   const [saving, setSaving] = useState(false);
//   const [scanning, setScanning] = useState(false);
//   const [fixingAll, setFixingAll] = useState(false);
//   const [fixingIssueId, setFixingIssueId] = useState<string | null>(null);
//   const [testingAws, setTestingAws] = useState(false);
//   const [awsConnection, setAwsConnection] = useState<"unknown" | "connected" | "failed">("unknown");

//   const refreshDashboard = useCallback(async () => {
//     setApiError(null);

//     const results = await Promise.allSettled([
//       fetchJson<Scan | null>("/api/scans/latest"),
//       fetchJson<ActivityItem[]>("/api/activity"),
//       fetchJson<ScanHistoryItem[]>("/api/scans/history"),
//       fetchJson<SafeOpsSettings>("/api/settings"),
//       fetchJson<FixHistoryItem[]>("/api/fix-history"),
//     ]);

//     const [scanResult, activityResult, historyResult, settingsResult, fixHistoryResult] = results;
//     const failures = results.filter((result) => result.status === "rejected") as PromiseRejectedResult[];

//     if (scanResult.status === "fulfilled") setScan(scanResult.value);
//     else setScan(null);

//     if (activityResult.status === "fulfilled") setActivity(Array.isArray(activityResult.value) ? activityResult.value : []);
//     else setActivity([]);

//     if (historyResult.status === "fulfilled") setHistory(Array.isArray(historyResult.value) ? historyResult.value : []);
//     else setHistory([]);

//     if (settingsResult.status === "fulfilled") setSettings(settingsResult.value ?? {});
//     else setSettings({});

//     if (fixHistoryResult.status === "fulfilled") setFixHistory(Array.isArray(fixHistoryResult.value) ? fixHistoryResult.value : []);
//     else setFixHistory([]);

//     if (failures.length > 0) {
//       setApiError(failures[0]?.reason?.message || "SafeOps API is unavailable. Check NEXT_PUBLIC_API_URL and backend health.");
//     }

//     setInitialLoading(false);
//   }, []);

//   useEffect(() => {
//     refreshDashboard();
//   }, [refreshDashboard]);

//   const sortedFindings = useMemo(() => {
//     return [...(scan?.findings ?? [])].sort((a, b) => {
//       const severityDelta = (severityRank[normalizeSeverity(b.severity)] ?? 0) - (severityRank[normalizeSeverity(a.severity)] ?? 0);
//       if (severityDelta !== 0) return severityDelta;
//       return (a.remediation_priority || "").localeCompare(b.remediation_priority || "");
//     });
//   }, [scan?.findings]);

//   const topRisk = sortedFindings[0];
//   const highSignalCount = sortedFindings.filter((finding) => highSignalSeverities.has(normalizeSeverity(finding.severity))).length;
//   const lastScan = history[history.length - 1]?.created_at;
//   const riskLevel = scan?.risk_level ?? "Unknown";
//   const slackReady = isValidSlackWebhook(settings?.slack_webhook_url);
//   const awsReady = Boolean(settings?.aws_region || settings?.role_arn || awsConnection === "connected");

//   const runScan = async () => {
//     setScanning(true);
//     setApiError(null);

//     try {
//       const data = await fetchJson<{ message?: string; detail?: string }>("/api/scan/run", { method: "POST" });
//       toast.success(data.message || "Scan completed");
//       if (!slackReady) toast("Add a Slack webhook to receive critical risk alerts.");
//       window.setTimeout(() => refreshDashboard(), 1200);
//     } catch (error) {
//       const message = error instanceof Error ? error.message : "Scan failed. Check backend logs.";
//       setApiError(message);
//       toast.error(message);
//     } finally {
//       setScanning(false);
//     }
//   };

//   const applyFix = async (finding: Finding) => {
//     setFixingIssueId(finding.fingerprint);
//     setApiError(null);

//     try {
//       const data = await fetchJson<{ message?: string; detail?: string }>("/api/fix", {
//         method: "POST",
//         body: JSON.stringify({ issue_id: finding.fingerprint }),
//       });
//       toast.success(data.message || "Fix applied");
//       window.setTimeout(() => refreshDashboard(), 1200);
//     } catch (error) {
//       const message = error instanceof Error ? error.message : "Fix failed";
//       const friendly = message.includes("already") ? "Issue already resolved. Refreshing state." : message;
//       toast.error(friendly);
//       setApiError(friendly);
//       if (message.includes("already")) window.setTimeout(() => refreshDashboard(), 900);
//     } finally {
//       setFixingIssueId(null);
//     }
//   };

//   const applyAllHighSignalFixes = async () => {
//     const confirmed = window.confirm("SafeOps will apply all supported high-signal fixes. Continue?");
//     if (!confirmed) return;

//     setFixingAll(true);
//     setApiError(null);

//     try {
//       const data = await fetchJson<{ message?: string; detail?: string }>("/api/fix", {
//         method: "POST",
//         body: JSON.stringify({ all_critical: true }),
//       });
//       toast.success(data.message || "High-signal fixes applied");
//       window.setTimeout(() => refreshDashboard(), 1200);
//     } catch (error) {
//       const message = error instanceof Error ? error.message : "Fix All failed";
//       const friendly = message.includes("already") ? "Some issues were already resolved. Refreshing state." : message;
//       toast.error(friendly);
//       setApiError(friendly);
//       if (message.includes("already")) window.setTimeout(() => refreshDashboard(), 900);
//     } finally {
//       setFixingAll(false);
//     }
//   };

//   const saveSettings = async () => {
//     if (!settings) return;
//     setSaving(true);
//     setApiError(null);

//     try {
//       const data = await fetchJson<{ message?: string; detail?: string }>("/api/settings", {
//         method: "POST",
//         body: JSON.stringify(settings),
//       });
//       toast.success(data.message || "Settings saved");
//       refreshDashboard();
//     } catch (error) {
//       const message = error instanceof Error ? error.message : "Settings update failed";
//       setApiError(message);
//       toast.error(message);
//     } finally {
//       setSaving(false);
//     }
//   };

//   const testAwsConnection = async () => {
//     setTestingAws(true);
//     setApiError(null);

//     try {
//       const data = await fetchJson<AwsTestResult>("/api/settings/test-aws", { method: "POST" });
//       if (data.success) {
//         setAwsConnection("connected");
//         toast.success(`Connected${data.account_id ? `: ${data.account_id}` : ""}`);
//       } else {
//         setAwsConnection("failed");
//         toast.error(data.message || data.detail || "AWS connection failed");
//       }
//     } catch (error) {
//       const message = error instanceof Error ? error.message : "AWS connection test failed";
//       setAwsConnection("failed");
//       setApiError(message);
//       toast.error(message);
//     } finally {
//       setTestingAws(false);
//     }
//   };

//   if (initialLoading) {
//     return (
//       <main className="min-h-screen bg-[#05070b] text-white">
//         <div className="flex min-h-screen items-center justify-center p-6">
//           <div className="relative w-full max-w-md overflow-hidden rounded-[2rem] border border-white/10 bg-slate-950/80 p-8 text-center shadow-2xl shadow-cyan-950/20">
//             <div className="absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/70 to-transparent" />
//             <Loader2 className="mx-auto h-10 w-10 animate-spin text-cyan-300" />
//             <h1 className="mt-5 text-2xl font-semibold tracking-tight">Starting SafeOps cockpit</h1>
//             <p className="mt-3 text-sm leading-6 text-slate-400">Loading AWS posture, findings, settings, audit history, and trend data from the configured SafeOps API.</p>
//           </div>
//         </div>
//       </main>
//     );
//   }

//   return (
//     <main className="min-h-screen bg-[#05070b] text-slate-100 selection:bg-cyan-300 selection:text-slate-950">
//       {(scanning || fixingAll) && (
//         <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-6 backdrop-blur-md">
//           <motion.div
//             initial={{ opacity: 0, scale: 0.96, y: 12 }}
//             animate={{ opacity: 1, scale: 1, y: 0 }}
//             className="w-full max-w-lg overflow-hidden rounded-[2rem] border border-cyan-300/20 bg-[#07101a] p-7 shadow-2xl shadow-cyan-950/40"
//           >
//             <div className="flex items-start gap-4">
//               <div className="relative flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border border-cyan-300/20 bg-cyan-400/10">
//                 <span className="absolute h-10 w-10 animate-ping rounded-full border border-cyan-300/30" />
//                 <Loader2 className="h-6 w-6 animate-spin text-cyan-200" />
//               </div>
//               <div>
//                 <p className="font-mono text-[0.68rem] uppercase tracking-[0.28em] text-cyan-300/80">Operation in progress</p>
//                 <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white">
//                   {scanning ? "Scanning your AWS account" : "Applying supported remediations"}
//                 </h2>
//                 <p className="mt-2 text-sm leading-6 text-slate-400">
//                   {scanning
//                     ? "Checking public SSH exposure, S3 access, RDS exposure, IAM trust policies, and other high-signal risks."
//                     : "SafeOps is applying backend-supported fixes and will refresh posture data when complete."}
//                 </p>
//               </div>
//             </div>
//           </motion.div>
//         </div>
//       )}

//       <aside className="fixed inset-y-0 left-0 z-30 hidden w-72 border-r border-white/10 bg-[#060a10]/90 px-5 py-6 backdrop-blur-xl lg:block">
//         <div className="flex items-center gap-3">
//           <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-300/20 bg-cyan-400/10 text-cyan-200 shadow-lg shadow-cyan-950/30">
//             <ShieldCheck className="h-5 w-5" />
//           </div>
//           <div>
//             <p className="text-lg font-semibold tracking-tight text-white">SafeOps</p>
//             <p className="font-mono text-[0.65rem] uppercase tracking-[0.24em] text-slate-500">Cloud posture</p>
//           </div>
//         </div>

//         <nav className="mt-10 space-y-1 text-sm">
//           {[
//             ["#overview", Gauge, "Posture overview"],
//             ["#findings", ShieldAlert, "Active findings"],
//             ["#trend", History, "Risk trend"],
//             ["#activity", Activity, "Activity"],
//             ["#audit", FileClock, "Fix audit trail"],
//             ["#settings", Settings2, "Settings"],
//           ].map(([href, Icon, label]) => {
//             const NavIcon = Icon as typeof Gauge;
//             return (
//               <a key={String(href)} href={String(href)} className="group flex items-center justify-between rounded-2xl px-3 py-2.5 text-slate-400 transition hover:bg-white/5 hover:text-white">
//                 <span className="flex items-center gap-3">
//                   <NavIcon className="h-4 w-4 text-cyan-300/70" />
//                   {String(label)}
//                 </span>
//                 <ChevronRight className="h-3.5 w-3.5 opacity-0 transition group-hover:opacity-100" />
//               </a>
//             );
//           })}
//         </nav>

//         <div className="absolute bottom-6 left-5 right-5 rounded-[1.4rem] border border-white/10 bg-slate-950/80 p-4">
//           <p className="font-mono text-[0.65rem] uppercase tracking-[0.24em] text-slate-500">Integration status</p>
//           <div className="mt-4 space-y-3 text-sm">
//             <div className="flex items-center justify-between gap-3">
//               <span className="flex items-center gap-2 text-slate-300"><CloudCog className="h-4 w-4 text-cyan-300" />AWS</span>
//               <span className={`rounded-full border px-2 py-0.5 text-xs ${awsReady ? "border-emerald-300/30 bg-emerald-400/10 text-emerald-200" : "border-amber-300/30 bg-amber-400/10 text-amber-100"}`}>
//                 {awsReady ? "Configured" : "Needs setup"}
//               </span>
//             </div>
//             <div className="flex items-center justify-between gap-3">
//               <span className="flex items-center gap-2 text-slate-300"><MessageSquare className="h-4 w-4 text-cyan-300" />Slack</span>
//               <span className={`rounded-full border px-2 py-0.5 text-xs ${slackReady ? "border-emerald-300/30 bg-emerald-400/10 text-emerald-200" : "border-amber-300/30 bg-amber-400/10 text-amber-100"}`}>
//                 {slackReady ? "Alerts on" : "Not enabled"}
//               </span>
//             </div>
//           </div>
//         </div>
//       </aside>

//       <div className="safeops-grid pointer-events-none fixed inset-0 opacity-35" />
//       <div className="safeops-noise pointer-events-none fixed inset-0 opacity-[0.08]" />

//       <div className="relative lg:pl-72">
//         <header className="sticky top-0 z-20 border-b border-white/10 bg-[#05070b]/78 px-5 py-4 backdrop-blur-xl md:px-8">
//           <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
//             <div>
//               <div className="flex items-center gap-2 text-sm text-slate-400 lg:hidden">
//                 <ShieldCheck className="h-4 w-4 text-cyan-300" /> SafeOps
//               </div>
//               <h1 className="mt-1 text-2xl font-semibold tracking-tight text-white md:text-3xl">Security posture command center</h1>
//               <p className="mt-1 text-sm leading-6 text-slate-400">Scan AWS, prioritize high-signal risks, and remediate supported findings from one founder-friendly control plane.</p>
//             </div>
//             <div className="flex flex-wrap gap-3">
//               <button onClick={refreshDashboard} className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-2.5 text-sm font-medium text-slate-200 transition hover:border-cyan-300/30 hover:bg-cyan-300/10">
//                 <RefreshCw className="h-4 w-4" /> Refresh
//               </button>
//               <button disabled={scanning} onClick={runScan} className="inline-flex items-center gap-2 rounded-2xl bg-cyan-300 px-4 py-2.5 text-sm font-semibold text-slate-950 shadow-lg shadow-cyan-950/30 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-60">
//                 {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <RadioTower className="h-4 w-4" />} Run scan
//               </button>
//             </div>
//           </div>
//         </header>

//         <div className="space-y-6 px-5 py-6 md:px-8 xl:px-10">
//           {apiError ? (
//             <div className="rounded-[1.4rem] border border-amber-300/25 bg-amber-400/10 p-4 text-amber-50 shadow-lg shadow-amber-950/20">
//               <div className="flex items-start gap-3">
//                 <AlertCircle className="mt-0.5 h-5 w-5 text-amber-200" />
//                 <div>
//                   <p className="font-semibold">SafeOps API needs attention</p>
//                   <p className="mt-1 text-sm leading-6 text-amber-100/80">{apiError}</p>
//                   <p className="mt-1 font-mono text-xs text-amber-100/60">NEXT_PUBLIC_API_URL: {API_BASE || "not set; using same-origin requests"}</p>
//                 </div>
//               </div>
//             </div>
//           ) : null}

//           <section id="overview" className="grid gap-6 xl:grid-cols-[minmax(0,1.55fr)_minmax(360px,0.75fr)]">
//             <motion.div
//               initial={{ opacity: 0, y: 18 }}
//               animate={{ opacity: 1, y: 0 }}
//               className="relative min-h-[430px] overflow-hidden rounded-[2rem] border border-white/10 bg-slate-950 p-6 shadow-2xl shadow-black/30 md:p-8"
//             >
//               <img src={HERO_IMAGE} alt="Abstract AWS topology visualization" className="absolute inset-0 h-full w-full object-cover opacity-55" />
//               <div className="absolute inset-0 bg-gradient-to-r from-[#05070b] via-[#05070b]/88 to-[#05070b]/30" />
//               <div className="relative flex h-full max-w-3xl flex-col justify-between gap-10">
//                 <div>
//                   <div className="inline-flex items-center gap-2 rounded-full border border-cyan-300/20 bg-cyan-300/10 px-3 py-1.5 font-mono text-[0.68rem] uppercase tracking-[0.24em] text-cyan-200">
//                     <Sparkles className="h-3.5 w-3.5" /> Startup cloud security
//                   </div>
//                   <h2 className="mt-6 max-w-2xl text-4xl font-semibold tracking-[-0.045em] text-white md:text-6xl">
//                     Find and fix AWS exposure before it becomes an incident.
//                   </h2>
//                   <p className="mt-5 max-w-xl text-base leading-8 text-slate-300">
//                     SafeOps turns public SSH, S3, RDS, and IAM trust policy checks into a live remediation cockpit for small teams that need security signal without enterprise overhead.
//                   </p>
//                 </div>
//                 <div className="grid gap-3 sm:grid-cols-3">
//                   <div className="rounded-2xl border border-white/10 bg-black/30 p-4 backdrop-blur">
//                     <p className="font-mono text-[0.65rem] uppercase tracking-[0.22em] text-slate-500">Risk score</p>
//                     <p className="mt-2 text-3xl font-semibold text-white">{scan ? `${scan.risk_score}/100` : "—"}</p>
//                   </div>
//                   <div className="rounded-2xl border border-white/10 bg-black/30 p-4 backdrop-blur">
//                     <p className="font-mono text-[0.65rem] uppercase tracking-[0.22em] text-slate-500">Risk level</p>
//                     <p className={`mt-2 inline-flex rounded-full border px-3 py-1 text-sm font-semibold ${riskTone(riskLevel)}`}>{riskLevel}</p>
//                   </div>
//                   <div className="rounded-2xl border border-white/10 bg-black/30 p-4 backdrop-blur">
//                     <p className="font-mono text-[0.65rem] uppercase tracking-[0.22em] text-slate-500">Last scan</p>
//                     <p className="mt-2 text-sm font-medium text-slate-200">{lastScan ? formatUserDateTime(lastScan) : "No scan yet"}</p>
//                   </div>
//                 </div>
//               </div>
//             </motion.div>

//             <div className="grid gap-6">
//               <div className="relative overflow-hidden rounded-[2rem] border border-white/10 bg-slate-950 p-5 shadow-2xl shadow-black/25">
//                 <img src={RISK_IMAGE} alt="Risk meter instrumentation" className="absolute inset-0 h-full w-full object-cover opacity-35" />
//                 <div className="absolute inset-0 bg-gradient-to-b from-slate-950/30 via-slate-950/75 to-slate-950" />
//                 <div className="relative">
//                   <p className="font-mono text-[0.68rem] uppercase tracking-[0.28em] text-cyan-300/75">Posture instrument</p>
//                   <div className="mt-24 rounded-2xl border border-white/10 bg-black/35 p-4 backdrop-blur">
//                     <div className="flex items-end justify-between gap-4">
//                       <div>
//                         <p className="text-5xl font-semibold tracking-tight text-white">{scan?.risk_score ?? "—"}</p>
//                         <p className="mt-1 text-sm text-slate-400">Current risk score</p>
//                       </div>
//                       <span className={`rounded-full border px-3 py-1 text-sm font-semibold ${riskTone(riskLevel)}`}>{riskLevel}</span>
//                     </div>
//                   </div>
//                 </div>
//               </div>

//               <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
//                 <MetricCard icon={ShieldAlert} label="Active findings" value={scan?.findings?.length ?? 0} detail="Issues requiring review or remediation." tone={scan?.findings?.length ? "amber" : "green"} />
//                 <MetricCard icon={Zap} label="High-signal queue" value={highSignalCount} detail="Critical and high severity findings eligible for priority review." tone={highSignalCount ? "red" : "green"} />
//               </div>
//             </div>
//           </section>

//           {!scan ? (
//             <SectionShell id="onboarding" eyebrow="First run" title="Connect AWS, configure alerts, then run your first scan" description="The backend returned no latest scan. SafeOps can still guide setup without inventing production data.">
//               <div className="grid gap-4 lg:grid-cols-3">
//                 <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-5">
//                   <CloudCog className="h-6 w-6 text-cyan-200" />
//                   <h3 className="mt-4 font-semibold text-white">1. Confirm AWS scope</h3>
//                   <p className="mt-2 text-sm leading-6 text-slate-400">Set AWS region and optional role ARN in settings so the scanner uses the intended account boundary.</p>
//                 </div>
//                 <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-5">
//                   <MessageSquare className="h-6 w-6 text-cyan-200" />
//                   <h3 className="mt-4 font-semibold text-white">2. Add Slack alerts</h3>
//                   <p className="mt-2 text-sm leading-6 text-slate-400">Paste a Slack incoming webhook to notify the team when critical findings appear.</p>
//                 </div>
//                 <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-5">
//                   <RadioTower className="h-6 w-6 text-cyan-200" />
//                   <h3 className="mt-4 font-semibold text-white">3. Run initial scan</h3>
//                   <p className="mt-2 text-sm leading-6 text-slate-400">Start a manual scan and SafeOps will populate posture, findings, trend, activity, and audit history.</p>
//                 </div>
//               </div>
//               <button disabled={scanning} onClick={runScan} className="mt-6 inline-flex items-center gap-2 rounded-2xl bg-cyan-300 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:opacity-60">
//                 {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <RadioTower className="h-4 w-4" />} Run first scan
//               </button>
//             </SectionShell>
//           ) : null}

//           <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
//             <MetricCard icon={Gauge} label="Current score" value={scan ? `${scan.risk_score}/100` : "—"} detail="Lower is better; calculated by the latest backend scan." tone="cobalt" />
//             <MetricCard icon={AlertTriangle} label="Priority risk" value={topRisk ? topRisk.severity.toUpperCase() : "Clear"} detail={topRisk ? topRisk.title : "No active high-risk finding is currently reported."} tone={topRisk ? "amber" : "green"} />
//             <MetricCard icon={Clock3} label="Scan cadence" value={settings?.scan_frequency || "Backend"} detail="Scheduled scans are handled by the existing backend." tone="cobalt" />
//             <MetricCard icon={CheckCircle2} label="Slack alerts" value={slackReady ? "Enabled" : "Setup"} detail={slackReady ? "Critical alerts are configured." : "Add a webhook to alert the team."} tone={slackReady ? "green" : "amber"} />
//           </div>

//           {topRisk ? (
//             <section className="relative overflow-hidden rounded-[2rem] border border-red-300/25 bg-red-500/10 p-5 shadow-2xl shadow-red-950/20 md:p-6">
//               <div className="absolute right-0 top-0 h-40 w-64 rounded-full bg-red-400/10 blur-3xl" />
//               <div className="relative flex flex-col gap-5 xl:flex-row xl:items-center xl:justify-between">
//                 <div>
//                   <p className="font-mono text-[0.68rem] uppercase tracking-[0.28em] text-red-200/80">Priority risk</p>
//                   <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white">{topRisk.title}</h2>
//                   <p className="mt-2 max-w-3xl text-sm leading-6 text-red-50/75">{topRisk.raw?.why_it_matters || "This misconfiguration may expose your infrastructure to attackers and should be reviewed before lower-signal findings."}</p>
//                   <div className="mt-4 flex flex-wrap gap-2">
//                     <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${severityTone(topRisk.severity)}`}>{topRisk.severity.toUpperCase()}</span>
//                     <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-slate-300">{topRisk.remediation_priority || "Review"}</span>
//                     <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 font-mono text-xs text-slate-400">{topRisk.fingerprint}</span>
//                   </div>
//                 </div>
//                 <button
//                   disabled={!!fixingIssueId || !canShowFixButton(topRisk)}
//                   onClick={() => applyFix(topRisk)} className="inline-flex shrink-0 items-center justify-center gap-2 rounded-2xl bg-red-300 px-5 py-3 text-sm font-semibold text-red-950 transition hover:bg-red-200 disabled:cursor-not-allowed disabled:opacity-60">
//                   {fixingIssueId === topRisk.fingerprint ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wand2 className="h-4 w-4" />} Fix top risk
//                 </button>
//               </div>
//             </section>
//           ) : null}

//           {scan && sortedFindings.length > 0 ? (
//             <section className="rounded-[1.6rem] border border-cyan-300/20 bg-cyan-400/10 p-5 shadow-2xl shadow-cyan-950/20">
//               <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
//                 <div>
//                   <p className="font-mono text-[0.68rem] uppercase tracking-[0.28em] text-cyan-200/80">Remediation queue</p>
//                   <h2 className="mt-2 text-xl font-semibold text-white">One-click hardening is available</h2>
//                   <p className="mt-1 text-sm leading-6 text-slate-300">Apply all backend-supported high-signal fixes, then refresh posture and audit history automatically.</p>
//                 </div>
//                 <button disabled={fixingAll || highSignalCount === 0} onClick={applyAllHighSignalFixes} className="inline-flex items-center justify-center gap-2 rounded-2xl bg-cyan-300 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-60">
//                   {fixingAll ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />} Fix all high-signal
//                 </button>
//               </div>
//             </section>
//           ) : null}

//           <div className="grid gap-6 xl:grid-cols-[minmax(0,1.25fr)_minmax(360px,0.75fr)]">
//             <SectionShell id="findings" eyebrow="Exposure inventory" title="Active findings" description="Findings are sorted by severity and remediation priority while preserving the backend-provided issue identifiers.">
//               {scan && sortedFindings.length === 0 ? (
//                 <EmptyState icon={CheckCircle2} title="No active findings in the latest scan" description="SafeOps did not report high-signal exposure. Keep scheduled scans active so drift is detected early." />
//               ) : sortedFindings.length > 0 ? (
//                 <div className="space-y-3">
//                   {sortedFindings.map((finding) => {
//                     const isFixing = fixingIssueId === finding.fingerprint;
//                     return (
//                       <motion.article key={finding.id || finding.fingerprint} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl border border-white/10 bg-black/25 p-4 transition hover:border-cyan-300/25 hover:bg-cyan-300/[0.04]">
//                         <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
//                           <div className="min-w-0">
//                             <div className="flex flex-wrap items-center gap-2">
//                               <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${severityTone(finding.severity)}`}>{finding.severity.toUpperCase()}</span>
//                               <span className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs text-slate-300">{finding.remediation_priority || "Review"}</span>
//                               <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${fixPriorityTone(finding.raw?.fix_priority)}`}>
//                                 {fixPriorityLabel(finding.raw?.fix_priority)}
//                               </span>
//                             </div>
//                             <h3 className="mt-3 text-base font-semibold text-white">{finding.title}</h3>
//                             <p className="mt-2 text-sm leading-6 text-slate-400">{finding.raw?.why_it_matters || "Review the resource configuration and apply the supported remediation if this exposure is unintended."}</p>
//                             {finding.raw?.fix_reason ? (
//                               <p className="mt-2 text-sm leading-6 text-slate-500">
//                                 Fix guidance: {finding.raw.fix_reason}
//                               </p>
//                             ) : null}
//                             <p className="mt-3 truncate font-mono text-xs text-slate-500">Issue fingerprint: {finding.fingerprint}</p>
//                           </div>
//                           <button
//                             disabled={!!fixingIssueId || !canShowFixButton(finding)}
//                             onClick={() => applyFix(finding)} className="inline-flex shrink-0 items-center justify-center gap-2 rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-2.5 text-sm font-semibold text-slate-100 transition hover:border-cyan-300/30 hover:bg-cyan-300/10 disabled:cursor-not-allowed disabled:opacity-60">
//                             {isFixing ? (
//                               <Loader2 className="h-4 w-4 animate-spin" />
//                             ) : (
//                               <LockKeyhole className="h-4 w-4" />
//                             )}
//                             {canShowFixButton(topRisk) ? "Fix top risk" : "Review required"}
//                           </button>
//                         </div>
//                       </motion.article>
//                     );
//                   })}
//                 </div>
//               ) : (
//                 <EmptyState icon={ShieldCheck} title="No latest scan loaded" description="Run the first scan or check API connectivity to populate active findings." action={<button onClick={runScan} className="rounded-2xl bg-cyan-300 px-4 py-2.5 text-sm font-semibold text-slate-950">Run scan</button>} />
//               )}
//             </SectionShell>

//             <SectionShell id="activity" eyebrow="Live operations" title="Activity timeline" description="Scan, alert, and remediation events from the existing backend activity feed.">
//               {activity.length === 0 ? (
//                 <EmptyState icon={Activity} title="No activity yet" description="Scan runs, settings changes, Slack alerts, and fix attempts will appear here as the backend records them." />
//               ) : (
//                 <ol className="relative space-y-5 border-l border-white/10 pl-5">
//                   {activity.slice(0, 8).map((item) => (
//                     <li key={item.id} className="relative">
//                       <span className="absolute -left-[1.69rem] top-1 flex h-3 w-3 rounded-full bg-cyan-300 shadow-lg shadow-cyan-300/40" />
//                       <p className="font-medium capitalize text-white">{item.action}</p>
//                       <p className="mt-1 text-sm leading-6 text-slate-400">{item.details}</p>
//                       <p className="mt-1 font-mono text-xs text-slate-600">{formatUserDateTime(item.created_at)}</p>
//                     </li>
//                   ))}
//                 </ol>
//               )}
//             </SectionShell>
//           </div>

//           <div className="grid gap-6 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
//             <SectionShell id="trend" eyebrow="Posture telemetry" title="Risk trend" description="Historical risk score from `/api/scans/history`, shown without synthetic production data.">
//               {history.length === 0 ? (
//                 <EmptyState icon={History} title="No trend history yet" description="Run multiple scans to build a posture trend and see whether remediation is lowering risk over time." />
//               ) : (
//                 <div className="h-80 rounded-2xl border border-white/10 bg-black/25 p-3">
//                   <ResponsiveContainer width="100%" height="100%">
//                     <LineChart data={history} margin={{ top: 18, right: 18, left: 0, bottom: 8 }}>
//                       <CartesianGrid stroke="rgba(148, 163, 184, 0.12)" vertical={false} />
//                       <XAxis dataKey="created_at" tick={{ fill: "#64748b", fontSize: 11 }} tickLine={false} axisLine={false} tickFormatter={shortTime} />
//                       <YAxis tick={{ fill: "#64748b", fontSize: 11 }} tickLine={false} axisLine={false} width={36} domain={[0, 100]} />
//                       <Tooltip
//                         contentStyle={{ background: "#020617", border: "1px solid rgba(255,255,255,0.12)", borderRadius: "16px", color: "#fff" }}
//                         labelFormatter={(label) => formatUserDateTime(String(label ?? ""))}
//                       />
//                       <Line type="monotone" dataKey="risk_score" stroke="#67e8f9" strokeWidth={3} dot={{ r: 3, fill: "#67e8f9" }} activeDot={{ r: 6, fill: "#fbbf24" }} />
//                     </LineChart>
//                   </ResponsiveContainer>
//                 </div>
//               )}
//             </SectionShell>

//             <SectionShell id="audit" eyebrow="Evidence trail" title="Fix audit trail" description="Every remediation attempt stays visible with status, message, timestamp, and before/after risk score.">
//               <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-black/25 p-4">
//                 <img src={AUDIT_IMAGE} alt="Abstract audit timeline" className="absolute inset-0 h-full w-full object-cover opacity-10" />
//                 <div className="relative">
//                   {fixHistory.length === 0 ? (
//                     <EmptyState icon={FileClock} title="No fixes recorded yet" description="When a single or bulk remediation runs, the backend fix history will populate this evidence trail." />
//                   ) : (
//                     <div className="space-y-3">
//                       {fixHistory.slice(0, 8).map((fix) => (
//                         <article key={fix.id} className="rounded-2xl border border-white/10 bg-slate-950/80 p-4 backdrop-blur">
//                           <div className="flex items-start justify-between gap-4">
//                             <div>
//                               <h3 className="font-semibold text-white">{fix.title}</h3>
//                               <p className="mt-1 text-sm leading-6 text-slate-400">{fix.message}</p>
//                               <p className="mt-2 font-mono text-xs text-slate-600">{formatUserDateTime(fix.created_at)}</p>
//                             </div>
//                             <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${fix.status === "success" ? "border-emerald-300/30 bg-emerald-400/10 text-emerald-200" : "border-red-300/30 bg-red-400/10 text-red-200"}`}>{fix.status.toUpperCase()}</span>
//                           </div>
//                           <div className="mt-3 flex items-center gap-2 text-sm text-slate-400">
//                             Risk {fix.before_risk_score}/100 <ArrowDownRight className="h-4 w-4 text-cyan-300" /> {fix.after_risk_score}/100
//                           </div>
//                         </article>
//                       ))}
//                     </div>
//                   )}
//                 </div>
//               </div>
//             </SectionShell>
//           </div>

//           <SectionShell id="settings" eyebrow="Control plane" title="Settings and integrations" description="Update AWS scan scope and Slack alerting while keeping all values routed through the existing `/api/settings` endpoint.">
//             <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
//               <div className="grid gap-4 md:grid-cols-2">
//                 <label className="block">
//                   <span className="font-mono text-[0.68rem] uppercase tracking-[0.24em] text-slate-500">AWS region</span>
//                   <input value={settings?.aws_region || ""} onChange={(event) => setSettings({ ...(settings || {}), aws_region: event.target.value })} placeholder="us-east-1" className="mt-2 w-full rounded-2xl border border-white/10 bg-black/35 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-300/40 focus:ring-4 focus:ring-cyan-300/10" />
//                 </label>
//                 <label className="block">
//                   <span className="font-mono text-[0.68rem] uppercase tracking-[0.24em] text-slate-500">Scan frequency</span>
//                   <input value={settings?.scan_frequency || ""} onChange={(event) => setSettings({ ...(settings || {}), scan_frequency: event.target.value })} placeholder="daily" className="mt-2 w-full rounded-2xl border border-white/10 bg-black/35 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-300/40 focus:ring-4 focus:ring-cyan-300/10" />
//                 </label>
//                 <label className="block md:col-span-2">
//                   <span className="font-mono text-[0.68rem] uppercase tracking-[0.24em] text-slate-500">Role ARN</span>
//                   <input value={settings?.role_arn || ""} onChange={(event) => setSettings({ ...(settings || {}), role_arn: event.target.value })} placeholder="arn:aws:iam::123456789012:role/SafeOpsScanner" className="mt-2 w-full rounded-2xl border border-white/10 bg-black/35 px-4 py-3 font-mono text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-300/40 focus:ring-4 focus:ring-cyan-300/10" />
//                 </label>
//                 <label className="block md:col-span-2">
//                   <span className="font-mono text-[0.68rem] uppercase tracking-[0.24em] text-slate-500">Slack webhook URL</span>
//                   <input value={settings?.slack_webhook_url || ""} onChange={(event) => setSettings({ ...(settings || {}), slack_webhook_url: event.target.value })} placeholder="https://hooks.slack.com/services/..." className="mt-2 w-full rounded-2xl border border-white/10 bg-black/35 px-4 py-3 font-mono text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-300/40 focus:ring-4 focus:ring-cyan-300/10" />
//                   <span className={`mt-2 inline-flex rounded-full border px-3 py-1 text-xs ${slackReady ? "border-emerald-300/30 bg-emerald-400/10 text-emerald-200" : settings?.slack_webhook_url ? "border-red-300/30 bg-red-400/10 text-red-200" : "border-amber-300/30 bg-amber-400/10 text-amber-100"}`}>
//                     {slackReady ? "Slack alerts enabled" : settings?.slack_webhook_url ? "Invalid Slack webhook URL" : "No Slack webhook configured"}
//                   </span>
//                 </label>
//                 <div className="flex flex-wrap gap-3 md:col-span-2">
//                   <button disabled={saving} onClick={saveSettings} className="inline-flex items-center gap-2 rounded-2xl bg-cyan-300 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-60">
//                     {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Settings2 className="h-4 w-4" />} Save settings
//                   </button>
//                   <button disabled={testingAws} onClick={testAwsConnection} className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.04] px-5 py-3 text-sm font-semibold text-white transition hover:border-emerald-300/30 hover:bg-emerald-300/10 disabled:cursor-not-allowed disabled:opacity-60">
//                     {testingAws ? <Loader2 className="h-4 w-4 animate-spin" /> : <TerminalSquare className="h-4 w-4" />} Test AWS connection
//                   </button>
//                 </div>
//               </div>

//               <div className="space-y-4">
//                 <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-5">
//                   <CloudCog className="h-5 w-5 text-cyan-200" />
//                   <h3 className="mt-3 font-semibold text-white">AWS guidance</h3>
//                   <p className="mt-2 text-sm leading-6 text-slate-400">Use the least-privilege scanner role expected by your backend. Test the connection before relying on scheduled scans.</p>
//                 </div>
//                 <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-5">
//                   <MessageSquare className="h-5 w-5 text-cyan-200" />
//                   <h3 className="mt-3 font-semibold text-white">Slack guidance</h3>
//                   <p className="mt-2 text-sm leading-6 text-slate-400">Critical issues should alert the shared engineering or founder channel where remediation ownership is clear.</p>
//                 </div>
//               </div>
//             </div>
//           </SectionShell>
//         </div>
//       </div>
//     </main>
//   );
// }


//v3


import { OverviewPage } from "@/components/safeops-views";

export default function Page() {
  return <OverviewPage />;
}
