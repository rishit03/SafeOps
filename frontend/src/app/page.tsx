"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ShieldCheck,
  Sparkles,
  Zap,
} from "lucide-react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

type Finding = {
  id: number;
  fingerprint: string;
  title: string;
  severity: string;
  remediation_priority?: string;
  raw?: {
    why_it_matters?: string;
    [key: string]: any;
  };
};

type Scan = {
  id: number;
  profile: string;
  risk_score: number;
  risk_level: string;
  findings: Finding[];
};

type ActivityItem = {
  id: number;
  action: string;
  details: string;
  created_at?: string;
};

type ScanHistoryItem = {
  id: number;
  risk_score: number;
  risk_level: string;
  created_at: string;
};

const formatUserDateTime = (value?: string) => {
  if (!value) return "Not available";

  return new Date(value).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
};

export default function Home() {
  const [scan, setScan] = useState<Scan | null>(null);
  const [fixing, setFixing] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [settings, setSettings] = useState<any>(null);

  const fetchScan = async () => {
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/scans/latest`);
      const data = await res.json();
      setScan(data);
    } catch {
      setScan(null);
    }
  };

  const fetchActivity = async () => {
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/activity`);
      const data = await res.json();
      setActivity(data);
    } catch {
      setActivity([]);
    }
  };

  const fetchHistory = async () => {
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/scans/history`);
      const data = await res.json();
      setHistory(data);
    } catch {
      setHistory([]);
    }
  };

  const fetchSettings = async () => {
    const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/settings`);
    const data = await res.json();
    setSettings(data);
  };

  const refreshDashboard = async () => {
    await fetchScan();
    await fetchActivity();
    await fetchHistory();
    await fetchSettings();
  };

  useEffect(() => {
    refreshDashboard();
  }, []);

  const runScan = async () => {
    setScanning(true);

    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/scan/run`, {
        method: "POST",
      });

      const data = await res.json();

      if (!res.ok) {
        toast.error(data.detail || "Scan failed. Check backend logs.");
        return;
      }

      toast.success(data.message || "Scan completed");

      setTimeout(() => {
        refreshDashboard();
      }, 1500);
    } catch {
      toast.error("Scan failed");
    } finally {
      setScanning(false);
    }
  };

  if (!scan) {
    return (
      <div className="h-screen flex items-center justify-center bg-black text-white">
        <div className="text-center max-w-md">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-blue-500/20 text-blue-400">
            <ShieldCheck size={24} />
          </div>

          <h1 className="text-3xl font-bold">SafeOps</h1>

          <p className="text-gray-400 mt-2">
            No scan data yet. Run your first cloud scan to populate the dashboard.
          </p>

          <button
            disabled={scanning}
            onClick={runScan}
            className={`mt-6 rounded-xl px-5 py-3 text-sm font-semibold transition ${
              scanning
                ? "bg-gray-700 opacity-70 cursor-not-allowed"
                : "bg-blue-500 hover:bg-blue-600 hover:scale-105 active:scale-95"
            }`}
          >
            {scanning ? "Scanning..." : "Run First Scan"}
          </button>
        </div>
      </div>
    );
  }

  const riskColor =
    scan.risk_level === "Critical"
      ? "text-red-500"
      : scan.risk_level === "High"
      ? "text-orange-400"
      : scan.risk_level === "Moderate"
      ? "text-yellow-400"
      : "text-green-400";

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.35 }}
      className="min-h-screen bg-black text-white"
    >
      {/* SCAN OVERLAY */}
      {scanning && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <motion.div
            initial={{ opacity: 0, scale: 0.92 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.2, ease: "easeOut" }}
            className="rounded-2xl border border-blue-500/30 bg-gray-950 p-8 shadow-2xl shadow-blue-500/20"
          >
            <div className="mx-auto mb-5 h-12 w-12 animate-spin rounded-full border-4 border-blue-500/20 border-t-blue-400" />

            <h2 className="text-center text-xl font-semibold">
              Scanning your AWS account
            </h2>

            <p className="mt-2 text-center text-sm text-gray-400">
              Checking S3, security groups, RDS, and IAM risks...
            </p>
          </motion.div>
        </div>
      )}

      {/* MAIN CONTENT */}
      <div className="mx-auto max-w-7xl px-8 py-12 space-y-6">
        <div>
          <h1 className="text-3xl font-bold">SafeOps Dashboard</h1>
          <p className="text-sm text-gray-500 mt-1">
            Real-time AWS security posture and automated remediation
          </p>
        </div>

        {/* Hero / SaaS landing header */}
        <div className="relative mb-10 overflow-hidden rounded-3xl border border-gray-800 bg-gradient-to-br from-gray-950 via-gray-900 to-black p-8">
          <div className="absolute right-0 top-0 h-64 w-64 rounded-full bg-blue-500/10 blur-3xl" />
          <div className="absolute bottom-0 left-20 h-48 w-48 rounded-full bg-green-500/10 blur-3xl" />

          <div className="relative flex flex-col gap-8 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-blue-500/30 bg-blue-500/10 px-3 py-1 text-sm text-blue-300">
                <Sparkles size={14} />
                AWS security command center for startups
              </div>

              <h1 className="max-w-3xl text-5xl font-bold tracking-tight">
                Find, prioritize, and fix cloud risks before they become incidents.
              </h1>

              <p className="mt-4 max-w-2xl text-gray-400">
                SafeOps turns AWS exposure checks into a live control plane:
                scan your account, understand what matters, and fix high-signal
                issues directly from the dashboard.
              </p>

              <div className="mt-6 flex flex-wrap gap-3">
                <button
                  disabled={scanning}
                  onClick={runScan}
                  className={`rounded-xl px-5 py-3 text-sm font-semibold transition ${
                    scanning
                      ? "bg-gray-700 opacity-70 cursor-not-allowed"
                      : "bg-blue-500 hover:bg-blue-600 hover:scale-105 active:scale-95 shadow-lg shadow-blue-500/20"
                  }`}
                >
                  {scanning ? "Scanning..." : "Run Scan"}
                </button>

                <button className="rounded-xl border border-gray-700 px-5 py-3 text-sm font-semibold text-gray-300 hover:border-gray-500 hover:text-white transition">
                  View Activity
                </button>
              </div>
            </div>

            <div className="rounded-2xl border border-gray-800 bg-black/40 p-5 shadow-2xl">
              <div className="mb-3 flex items-center gap-2 text-sm text-gray-400">
                <Zap size={16} className="text-yellow-400" />
                Current posture
              </div>

              <div className="text-5xl font-bold">{scan.risk_score}/100</div>
              <div className={`mt-2 text-lg font-semibold ${riskColor}`}>
                {scan.risk_level}
              </div>

              <div className="mt-4 text-sm text-gray-400">
                {scan.findings.length} active finding
                {scan.findings.length === 1 ? "" : "s"}
              </div>
              {history.length > 0 && (
                <div className="mt-2 text-xs text-gray-400">
                  Last scan:{" "}
                  {formatUserDateTime(history[history.length - 1]?.created_at)}
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="bg-gray-900 p-6 rounded-xl">
          <h2 className="text-xl font-semibold mb-4">Settings</h2>

          {!settings ? (
            <p className="text-gray-500">Loading settings...</p>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="text-sm text-gray-400">AWS Region</label>
                <input
                  value={settings.aws_region || ""}
                  onChange={(e) =>
                    setSettings({ ...settings, aws_region: e.target.value })
                  }
                  className="w-full mt-1 p-2 rounded bg-black border border-gray-700"
                />
              </div>

              <div>
                <label className="text-sm text-gray-400">Role ARN (optional)</label>
                <input
                  value={settings.role_arn || ""}
                  onChange={(e) =>
                    setSettings({ ...settings, role_arn: e.target.value })
                  }
                  className="w-full mt-1 p-2 rounded bg-black border border-gray-700"
                />
              </div>

              <div className="flex gap-3">
                <button
                  onClick={async () => {
                    const res = await fetch(
                      `${process.env.NEXT_PUBLIC_API_URL}/api/settings`,
                      {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(settings),
                      }
                    );
                    const data = await res.json();
                    toast.success(data.message);
                  }}
                  className="bg-blue-500 px-4 py-2 rounded"
                >
                  Save
                </button>

                <button
                  onClick={async () => {
                    const res = await fetch(
                      `${process.env.NEXT_PUBLIC_API_URL}/api/settings/test-aws`,
                      { method: "POST" }
                    );
                    const data = await res.json();

                    if (data.success) {
                      toast.success(`Connected: ${data.account_id}`);
                    } else {
                      toast.error(data.message);
                    }
                  }}
                  className="bg-green-500 px-4 py-2 rounded"
                >
                  Test Connection
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Metrics */}
        <div className="mb-8 grid grid-cols-1 gap-6 md:grid-cols-3">
          <motion.div
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
            className="rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-xl"
          >
            <p className="flex items-center gap-2 text-sm text-gray-400">
              <ShieldCheck size={16} />
              Risk Score
            </p>
            <p className="mt-3 text-4xl font-bold">{scan.risk_score}/100</p>
            <p className="mt-2 text-sm text-gray-500">
              Lower is better. Updated from latest scan.
            </p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45 }}
            className="rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-xl"
          >
            <p className="flex items-center gap-2 text-sm text-gray-400">
              <AlertTriangle size={16} />
              Risk Level
            </p>
            <p className={`mt-3 text-4xl font-bold ${riskColor}`}>
              {scan.risk_level}
            </p>
            <p className="mt-2 text-sm text-gray-500">
              Based on active high-signal findings.
            </p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-xl"
          >
            <p className="flex items-center gap-2 text-sm text-gray-400">
              <Activity size={16} />
              Active Findings
            </p>
            <p className="mt-3 text-4xl font-bold">{scan.findings.length}</p>
            <p className="mt-2 text-sm text-gray-500">
              Issues requiring review or action.
            </p>
          </motion.div>
        </div>

        {/* Primary Action */}
        {scan.findings.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.35 }}
            className="mb-6 flex items-center justify-between rounded-2xl border border-blue-500/20 bg-blue-500/10 p-5"
          >
            <div>
              <p className="font-semibold text-blue-200">
                One-click hardening available
              </p>
              <p className="text-sm text-gray-400">
                Apply all supported high-signal fixes, then refresh posture automatically.
              </p>
            </div>

            <button
              disabled={fixing}
              className={`rounded-xl px-5 py-3 text-sm font-semibold transition ${
                fixing
                  ? "bg-gray-700 opacity-70 cursor-not-allowed"
                  : "bg-blue-500 hover:bg-blue-600 hover:scale-105 active:scale-95 shadow-lg shadow-blue-500/20"
              }`}
              onClick={async () => {
                const confirmFix = confirm(
                  "This will fix all high-signal issues. Continue?"
                );
                if (!confirmFix) return;

                setFixing(true);

                try {
                  const res = await fetch(
                    `${process.env.NEXT_PUBLIC_API_URL}/api/fix`,
                    {
                      method: "POST",
                      headers: {
                        "Content-Type": "application/json",
                      },
                      body: JSON.stringify({
                        all_critical: true,
                      }),
                    }
                  );

                  const data = await res.json();

                  if (!res.ok) {
                    toast.error(
                      data.detail?.includes("already")
                        ? "Issue already resolved. Refreshing state."
                        : data.detail || "Action failed"
                    );
                    setFixing(false);
                    return;
                  }

                  toast.success(data.message || "Fixes applied");

                  setTimeout(() => {
                    refreshDashboard();
                    setFixing(false);
                  }, 1500);
                } catch {
                  toast.error("Fix All failed");
                  setFixing(false);
                }
              }}
            >
              {fixing ? "Fixing..." : "Fix All High-Signal"}
            </button>
          </motion.div>
        )}

        {/* Top Risk */}
        {scan.findings.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.35 }}
            className="relative mb-6 overflow-hidden rounded-2xl border border-red-500/50 bg-gradient-to-br from-red-950/40 via-gray-950 to-gray-950 p-6 shadow-2xl shadow-red-950/20"
          >
            <div className="absolute inset-0 bg-red-500/5 blur-2xl pointer-events-none" />

            <div className="relative flex items-center justify-between gap-6">
              <div>
                <div className="mb-3 flex items-center gap-2 text-red-400">
                  <AlertTriangle size={18} />
                  <h2 className="text-xl font-semibold">Top Risk</h2>
                </div>

                <p className="text-lg font-semibold">
                  {scan.findings[0].title}
                </p>

                <p className="mt-2 max-w-xl text-sm text-gray-400">
                  {scan.findings[0].raw?.why_it_matters ??
                    "This misconfiguration may expose your infrastructure to attackers."}
                </p>

                <div className="mt-3 flex flex-wrap gap-2">
                  <span
                    className={`rounded-full px-3 py-1 text-xs font-semibold ${
                      scan.findings[0].severity === "critical"
                        ? "bg-red-500/20 text-red-300"
                        : scan.findings[0].severity === "high"
                        ? "bg-orange-500/20 text-orange-300"
                        : "bg-gray-700 text-gray-300"
                    }`}
                  >
                    {scan.findings[0].severity.toUpperCase()}
                  </span>

                  <span className="rounded-full bg-gray-800 px-3 py-1 text-xs text-gray-300">
                    {scan.findings[0].remediation_priority || "Review"}
                  </span>
                </div>
              </div>

              <button
                disabled={fixing}
                onClick={async () => {
                  setFixing(true);

                  try {
                    const res = await fetch(
                      `${process.env.NEXT_PUBLIC_API_URL}/api/fix`,
                      {
                        method: "POST",
                        headers: {
                          "Content-Type": "application/json",
                        },
                        body: JSON.stringify({
                          issue_id: scan.findings[0].fingerprint,
                        }),
                      }
                    );

                    const data = await res.json();

                    if (!res.ok) {
                      toast.error(
                        data.detail?.includes("already")
                          ? "Issue already resolved. Refreshing state."
                          : data.detail || "Action failed"
                      );
                      setFixing(false);
                      return;
                    }

                    toast.success(data.message || "Fix applied");

                    setTimeout(() => {
                      refreshDashboard();
                      setFixing(false);
                    }, 1500);
                  } catch {
                    toast.error("Fix failed");
                    setFixing(false);
                  }
                }}
                className={`rounded-xl px-5 py-3 text-sm font-semibold transition ${
                  fixing
                    ? "bg-gray-700 opacity-70 cursor-not-allowed"
                    : "bg-red-500 hover:bg-red-600 hover:scale-105 active:scale-95 shadow-lg shadow-red-500/20"
                }`}
              >
                {fixing ? "Fixing..." : "Fix Now"}
              </button>
            </div>
          </motion.div>
        )}

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Findings Section */}
          <motion.div
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45 }}
            className="rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-xl"
          >
            <h2 className="mb-4 text-xl font-semibold">Findings</h2>

            {scan.findings.length === 0 ? (
              <div className="flex items-start gap-3 rounded-xl border border-green-500/20 bg-green-500/10 p-4">
                <CheckCircle2 className="mt-1 text-green-400" size={22} />
                <div>
                  <p className="text-green-400 text-lg font-medium">
                    Your cloud is secure
                  </p>
                  <p className="mt-1 text-sm text-gray-400">
                    No high-risk issues detected in the latest scan.
                  </p>
                  <p className="mt-2 text-xs text-gray-500">
                    Run periodic scans to ensure continuous protection.
                  </p>
                </div>
              </div>
            ) : (
              <motion.ul
                initial="hidden"
                animate="visible"
                variants={{
                  hidden: {},
                  visible: {
                    transition: {
                      staggerChildren: 0.08,
                    },
                  },
                }}
                className="space-y-4"
              >
                {scan.findings.map((f) => (
                  <motion.li
                    key={f.id}
                    variants={{
                      hidden: { opacity: 0, y: 10 },
                      visible: { opacity: 1, y: 0 },
                    }}
                    className="rounded-xl border border-gray-800 bg-black/30 p-4 transition hover:border-gray-600"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <p className="font-medium">{f.title}</p>
                        <span
                          className={`mt-2 inline-flex rounded-full px-2 py-1 text-xs font-semibold ${
                            f.severity === "critical"
                              ? "bg-red-500/20 text-red-400"
                              : f.severity === "high"
                              ? "bg-orange-500/20 text-orange-400"
                              : "bg-gray-700 text-gray-300"
                          }`}
                        >
                          {f.severity.toUpperCase()}
                        </span>
                      </div>

                      <span className="rounded-full bg-gray-800 px-3 py-1 text-xs text-gray-300">
                        {f.remediation_priority || "Review"}
                      </span>
                    </div>
                  </motion.li>
                ))}
              </motion.ul>
            )}
          </motion.div>

          {/* Activity Section */}
          <motion.div
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-xl"
          >
            <h2 className="mb-4 flex items-center gap-2 text-xl font-semibold">
              <Activity size={18} />
              Activity
            </h2>

            {activity.length === 0 ? (
              <p className="text-gray-500">No activity yet</p>
            ) : (
              <ul className="space-y-4 text-sm text-gray-400">
                {activity.map((a) => (
                  <li
                    key={a.id}
                    className="flex items-start gap-3 border-l border-gray-800 pl-4"
                  >
                    <span className="mt-1 h-2 w-2 rounded-full bg-blue-400 shadow-lg shadow-blue-400/40" />
                    <div>
                      <p className="font-medium text-white">
                        <span className="capitalize">{a.action}</span>
                      </p>
                      <p className="text-gray-300">{a.details}</p>
                      {a.created_at && (
                        <p className="mt-1 text-xs text-gray-600">
                          {formatUserDateTime(a.created_at)}
                        </p>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </motion.div>
        </div>

        {/* Risk Trend */}
        <motion.div
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.55 }}
          className="mt-6 rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-xl"
        >
          <h2 className="mb-4 text-xl font-semibold">Risk Trend</h2>

          {history.length === 0 ? (
            <p className="text-gray-500">No history yet</p>
          ) : (
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={history}>
                  <XAxis
                    dataKey="created_at"
                    tick={{ fill: "#9CA3AF", fontSize: 10 }}
                    tickFormatter={(v) =>
                      new Date(v).toLocaleTimeString(undefined, {
                        hour: "2-digit",
                        minute: "2-digit",
                      })
                    }
                  />
                  <YAxis tick={{ fill: "#9CA3AF", fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#030712",
                      border: "1px solid #374151",
                      borderRadius: "12px",
                      color: "#fff",
                    }}
                  />
                  <Line
                    type="monotone"
                    dataKey="risk_score"
                    stroke="#3B82F6"
                    strokeWidth={3}
                    dot={{ r: 3 }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </motion.div>
      </div>
    </motion.div>
  );
}