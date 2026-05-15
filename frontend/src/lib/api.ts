import type { ActivityItem, ApiBundle, AwsTestResponse, CloudAccount, FixHistoryItem, FixResponse, Scan, Settings } from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") || "";

class ApiError extends Error {
  endpoint: string;
  status?: number;

  constructor(endpoint: string, message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.endpoint = endpoint;
    this.status = status;
  }
}

async function request<T>(endpoint: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
    cache: "no-store",
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const payload = await response.json();
      detail = String(payload.detail || payload.message || payload.error || detail);
    } catch {
      // Keep HTTP status text when body is not JSON.
    }
    throw new ApiError(endpoint, detail || `Request failed: ${response.status}`, response.status);
  }

  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

function errorMessage(reason: unknown): string {
  if (reason instanceof Error) return reason.message;
  return "Request failed";
}

export const safeopsApi = {
  latestScan: (accountId?: number | null) =>
    request<Scan | null>(
      accountId ? `/api/scans/latest?account_id=${accountId}` : "/api/scans/latest"
    ),
  scanHistory: () => request<Scan[]>("/api/scans/history"),
  runScan: (accountId?: number | null) =>
    request<Scan | { message?: string }>("/api/scan/run", {
      method: "POST",
      body: JSON.stringify({ account_id: accountId }),
    }),
  fixOne: (fingerprint: string) => request<FixResponse>("/api/fix", { method: "POST", body: JSON.stringify({ issue_id: fingerprint }) }),
  fixCritical: () => request<FixResponse>("/api/fix", { method: "POST", body: JSON.stringify({ all_critical: true }) }),
  activity: () => request<ActivityItem[]>("/api/activity"),
  fixHistory: () => request<FixHistoryItem[]>("/api/fix-history"),
  settings: () => request<Settings>("/api/settings"),
  saveSettings: (settings: Settings) => request<Settings>("/api/settings", { method: "POST", body: JSON.stringify(settings) }),
  testAws: (accountId?: number | null) =>
    request<AwsTestResponse>("/api/settings/test-aws", {
      method: "POST",
      body: JSON.stringify({ account_id: accountId }),
    }),
  cloudAccounts: () => request<CloudAccount[]>("/api/cloud-accounts"),
  graph: (accountId: number) =>
    request<{
      nodes: unknown[];
      edges: unknown[];
      attack_paths?: string[][];
    }>(`/api/graph?account_id=${accountId}`),
  assetDetails: (assetId: number) =>
    request(`/api/assets/${assetId}`),
};

export async function loadSafeOpsBundle(accountId?: number | null): Promise<ApiBundle> {
  const [latest, history, activity, fixHistory, settings, cloudAccounts] = await Promise.allSettled([
    safeopsApi.latestScan(accountId),
    safeopsApi.scanHistory(),
    safeopsApi.activity(),
    safeopsApi.fixHistory(),
    safeopsApi.settings(),
    safeopsApi.cloudAccounts(),
  ]);

  return {
    latest: latest.status === "fulfilled" ? latest.value : null,
    history: history.status === "fulfilled" && Array.isArray(history.value) ? history.value : [],
    activity: activity.status === "fulfilled" && Array.isArray(activity.value) ? activity.value : [],
    fixHistory: fixHistory.status === "fulfilled" && Array.isArray(fixHistory.value) ? fixHistory.value : [],
    settings: settings.status === "fulfilled" ? settings.value : null,
    cloudAccounts: cloudAccounts.status === "fulfilled" && Array.isArray(cloudAccounts.value) ? cloudAccounts.value : [],
    errors: {
      latest: latest.status === "rejected" ? errorMessage(latest.reason) : undefined,
      history: history.status === "rejected" ? errorMessage(history.reason) : undefined,
      activity: activity.status === "rejected" ? errorMessage(activity.reason) : undefined,
      fixHistory: fixHistory.status === "rejected" ? errorMessage(fixHistory.reason) : undefined,
      settings: settings.status === "rejected" ? errorMessage(settings.reason) : undefined,
      cloudAccounts: cloudAccounts.status === "rejected" ? errorMessage(cloudAccounts.reason) : undefined,
    },
  };
}
