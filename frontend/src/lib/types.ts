export type Severity = "critical" | "high" | "medium" | "low" | "info" | string;
export type FixLane = "auto" | "review" | "manual" | "unsupported";
export type RiskLevel = "critical" | "high" | "medium" | "low" | "unknown" | string;

export type FindingRaw = {
  why_it_matters?: string;
  fix_priority?: string;
  can_auto_fix?: boolean;
  fix_reason?: string;
  recommended_action?: string;
  sample_sensitive_object_keys?: string[];
  dangerous_actions?: string[];
  bucket_name?: string;
  role_name?: string;
  resource_type?: string;
  [key: string]: unknown;
};

export type Finding = {
  id?: string;
  fingerprint?: string;
  title?: string;
  severity?: Severity;
  remediation_priority?: string;
  module?: string;
  status?: string;
  raw?: FindingRaw;
  [key: string]: unknown;
};

export type Scan = {
  id?: string;
  cloud_account_id?: number | null;
  created_at?: string;
  timestamp?: string;
  scanned_at?: string;
  risk_score?: number;
  risk_level?: RiskLevel;
  findings?: Finding[];
  summary?: Record<string, unknown>;
  [key: string]: unknown;
};

export type ActivityItem = {
  id?: string;
  type?: string;
  action?: string;
  message?: string;
  created_at?: string;
  timestamp?: string;
  status?: string;
  [key: string]: unknown;
};

export type FixHistoryItem = {
  id?: string;
  issue_id?: string;
  fingerprint?: string;
  title?: string;
  status?: "success" | "failed" | "unsupported" | "manual_only" | "review_before_fix" | string;
  message?: string;
  before_risk_score?: number;
  after_risk_score?: number;
  created_at?: string;
  timestamp?: string;
  [key: string]: unknown;
};

export type Settings = {
  aws_region?: string;
  region?: string;
  role_arn?: string;
  scan_frequency_minutes?: number;
  scheduled_scan_frequency_minutes?: number;
  slack_webhook_url?: string;
  slack_enabled?: boolean;
  aws_connected?: boolean;
  slack_configured?: boolean;
  [key: string]: unknown;
};

export type ApiBundle = {
  latest: Scan | null;
  history: Scan[];
  activity: ActivityItem[];
  fixHistory: FixHistoryItem[];
  settings: Settings | null;
  cloudAccounts: CloudAccount[];
  errors: Partial<Record<"latest" | "history" | "activity" | "fixHistory" | "settings" | "cloudAccounts", string>>;
};

export type FixResponse = {
  status?: string;
  message?: string;
  fixed?: number;
  skipped?: number;
  results?: unknown[];
  [key: string]: unknown;
};

export type AwsTestResponse = {
  ok?: boolean;
  status?: string;
  message?: string;
  [key: string]: unknown;
};

export type NavKey =
  | "overview"
  | "findings"
  | "attack-paths"
  | "remediation"
  | "assets"
  | "activity"
  | "audit"
  | "integrations"
  | "connect"
  | "settings"
  | "planned";

  export type CloudAccount = {
  id: number;
  name: string;
  provider?: string;
  aws_account_id?: string | null;
  aws_region?: string;
  role_arn?: string | null;
  is_default?: boolean;
  status?: string;
  created_at?: string;
};