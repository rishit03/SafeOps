"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { toast } from "sonner";
import { loadSafeOpsBundle, safeopsApi } from "@/lib/api";
import type { ApiBundle, AwsTestResponse, Finding, FixResponse, Settings } from "@/lib/types";
import { canAutoFix, findingFingerprint, isValidSlackWebhook } from "@/lib/helpers";

const emptyBundle: ApiBundle = {
  latest: null,
  history: [],
  activity: [],
  fixHistory: [],
  settings: null,
  errors: {},
  cloudAccounts: [],
};

type SafeOpsContextValue = {
  bundle: ApiBundle;
  loading: boolean;
  refreshing: boolean;
  scanning: boolean;
  fixingAll: boolean;
  fixingOne: string | null;
  saving: boolean;
  testingAws: boolean;
  activeAccountId: number | null;
  refresh: () => Promise<void>;
  runScan: () => Promise<void>;
  fixFinding: (finding: Finding) => Promise<void>;
  fixCritical: () => Promise<void>;
  saveSettings: (settings: Settings) => Promise<void>;
  testAws: () => Promise<AwsTestResponse | null>;
  setActiveAccountId: (id: number | null) => void;
};

const SafeOpsContext = createContext<SafeOpsContextValue | null>(null);

function toastFixResponse(response: FixResponse, fallback: string) {
  const message = response.message || fallback;
  const status = String(response.status || "").toLowerCase();
  if (status.includes("fail") || status.includes("error")) toast.error(message);
  else if (status.includes("manual") || status.includes("unsupported") || status.includes("review")) toast.warning(message);
  else toast.success(message);
}

export function SafeOpsDataProvider({ children }: { children: ReactNode }) {
  const [bundle, setBundle] = useState<ApiBundle>(emptyBundle);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [fixingAll, setFixingAll] = useState(false);
  const [fixingOne, setFixingOne] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [testingAws, setTestingAws] = useState(false);
  const [activeAccountId, setActiveAccountId] = useState<number | null>(null);

  const refresh = useCallback(async () => {
    setRefreshing(true);

    try {
      const data = await loadSafeOpsBundle(activeAccountId);
      setBundle(data);
    } finally {
      setRefreshing(false);
      setLoading(false);
    }
  }, [activeAccountId]);

  useEffect(() => {
    async function initialLoad() {
      setLoading(true);

      try {
        const data = await loadSafeOpsBundle();
        setBundle(data);

        if (data.cloudAccounts.length) {
          const defaultAccount = data.cloudAccounts.find((account) => account.is_default);
          setActiveAccountId(defaultAccount?.id || data.cloudAccounts[0].id);
        }
      } finally {
        setLoading(false);
      }
    }

    initialLoad();
  }, []);

  useEffect(() => {
    if (!activeAccountId || loading) return;

    refresh();
  }, [activeAccountId]);

  const runScan = useCallback(async () => {
    const activeAccount = bundle.cloudAccounts.find(
      (account) => account.id === activeAccountId
    );

    if (activeAccount?.status !== "connected") {
      toast.warning("Test AWS connection before running a scan.");
      return;
    }
    setScanning(true);
    try {
      const response = await safeopsApi.runScan(activeAccountId);
      const message = response && typeof response === "object" && "message" in response && typeof response.message === "string" ? response.message : undefined;
      toast.success(message || "Scan completed");
      if (!isValidSlackWebhook(bundle.settings?.slack_webhook_url)) toast("Add Slack to receive alerts.");
      await new Promise((resolve) => setTimeout(resolve, 900));
      await refresh();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  }, [activeAccountId, bundle.cloudAccounts, bundle.settings?.slack_webhook_url, refresh]);

  const fixFinding = useCallback(async (finding: Finding) => {
    if (!canAutoFix(finding)) {
      toast.warning("This finding needs review or manual work.");
      return;
    }

    const fingerprint = String(findingFingerprint(finding));
    setFixingOne(fingerprint);
    try {
      const response = await safeopsApi.fixOne(fingerprint);
      toastFixResponse(response, "Fix action complete");
      await refresh();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Fix failed");
    } finally {
      setFixingOne(null);
    }
  }, [refresh]);

  const fixCritical = useCallback(async () => {
    setFixingAll(true);
    try {
      const response = await safeopsApi.fixCritical();
      toastFixResponse(response, "Supported critical remediations complete");
      await refresh();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Critical remediation failed");
    } finally {
      setFixingAll(false);
    }
  }, [refresh]);

  const saveSettings = useCallback(async (settings: Settings) => {
    setSaving(true);
    try {
      const saved = await safeopsApi.saveSettings(settings);
      setBundle((current) => ({ ...current, settings: saved }));
      toast.success("Settings saved");
      await refresh();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Settings save failed");
    } finally {
      setSaving(false);
    }
  }, [refresh]);

  const testAws = useCallback(async () => {
    setTestingAws(true);

    try {
      const response = await safeopsApi.testAws(activeAccountId);
      const responseRecord = response as AwsTestResponse & {
        success?: boolean;
        detail?: string;
      };

      if (
        responseRecord.ok ||
        responseRecord.success ||
        responseRecord.status === "success"
      ) {
        toast.success(responseRecord.message || "AWS connection verified");
        await refresh();
      } else {
        toast.warning(
          responseRecord.message ||
            responseRecord.detail ||
            "AWS test returned a warning"
        );
      }

      return response;
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "AWS test failed");
      return null;
    } finally {
      setTestingAws(false);
    }
  }, [activeAccountId, refresh]);

  const accountAwareBundle = useMemo(() => {
    if (!activeAccountId) return bundle;

    const latestBelongsToActiveAccount =
      bundle.latest?.cloud_account_id === activeAccountId;

    return {
      ...bundle,
      latest: latestBelongsToActiveAccount ? bundle.latest : null,
    };
  }, [bundle, activeAccountId]);

  const value = useMemo<SafeOpsContextValue>(() => ({
    bundle: accountAwareBundle,
    loading,
    refreshing,
    scanning,
    fixingAll,
    fixingOne,
    saving,
    testingAws,
    activeAccountId,
    refresh,
    runScan,
    fixFinding,
    fixCritical,
    saveSettings,
    testAws,
    setActiveAccountId,
  }), [accountAwareBundle, loading, refreshing, scanning, fixingAll, fixingOne, saving, testingAws, refresh, runScan, fixFinding, fixCritical, saveSettings, testAws]);

  return <SafeOpsContext.Provider value={value}>{children}</SafeOpsContext.Provider>;
}

export function useSafeOps() {
  const context = useContext(SafeOpsContext);
  if (!context) throw new Error("useSafeOps must be used inside SafeOpsDataProvider");
  return context;
}
