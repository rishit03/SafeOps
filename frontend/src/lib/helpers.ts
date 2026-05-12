import type { Finding, FixHistoryItem, RiskLevel, Scan, Severity } from "./types";

export function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

export function formatUserDateTime(value?: string) {
  if (!value) return "Not available";
  const utcValue = value.endsWith("Z") ? value : `${value}Z`;
  return new Date(utcValue).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function shortTime(value?: string) {
  if (!value) return "—";
  const utcValue = value.endsWith("Z") ? value : `${value}Z`;
  return new Date(utcValue).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function normalizeSeverity(value?: Severity) {
  return String(value || "unknown").toLowerCase();
}

export function riskLevelFromScore(score?: number): RiskLevel {
  if (typeof score !== "number") return "unknown";
  if (score >= 85) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

export function getRiskLevel(scan?: Scan | null) {
  return scan?.risk_level || riskLevelFromScore(scan?.risk_score);
}

export function riskTone(riskLevel?: string) {
  const level = String(riskLevel || "").toLowerCase();
  if (level.includes("critical")) return "tone-red";
  if (level.includes("high")) return "tone-orange";
  if (level.includes("moderate") || level.includes("medium")) return "tone-amber";
  if (level.includes("low")) return "tone-green";
  return "tone-slate";
}

export function severityTone(severity?: Severity) {
  const normalized = normalizeSeverity(severity);
  if (normalized === "critical") return "tone-red";
  if (normalized === "high") return "tone-orange";
  if (normalized === "medium" || normalized === "moderate") return "tone-amber";
  if (normalized === "low") return "tone-green";
  return "tone-slate";
}

export function severityRank(severity?: Severity) {
  const normalized = normalizeSeverity(severity);
  if (normalized === "critical") return 5;
  if (normalized === "high") return 4;
  if (normalized === "medium" || normalized === "moderate") return 3;
  if (normalized === "low") return 2;
  return 1;
}

export function sortFindings(findings: Finding[]) {
  return [...findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

export function highSignalFindings(findings: Finding[]) {
  return sortFindings(findings).filter((finding) => ["critical", "high"].includes(normalizeSeverity(finding.severity)));
}

export function fixPriorityLabel(priority?: string) {
  if (priority === "auto_fix_now") return "Auto-fix";
  if (priority === "review_before_fix") return "Review";
  if (priority === "manual_only") return "Manual";
  if (priority === "unsupported") return "Unsupported";
  return "Review";
}

export function fixPriorityTone(priority?: string) {
  if (priority === "auto_fix_now") return "tone-green";
  if (priority === "review_before_fix") return "tone-amber";
  if (priority === "manual_only") return "tone-slate";
  if (priority === "unsupported") return "tone-red";
  return "tone-slate";
}

export function canAutoFix(finding: Finding) {
  return finding.raw?.can_auto_fix === true;
}

export function findingFingerprint(finding: Finding) {
  return finding.fingerprint || finding.id || finding.title || "unknown-finding";
}

export function isValidSlackWebhook(url?: string) {
  return !!url && url.startsWith("https://hooks.slack.com/services/");
}

export function scanTimestamp(scan?: Scan | null) {
  return scan?.created_at || scan?.timestamp || scan?.scanned_at;
}

export function riskDelta(item: FixHistoryItem) {
  const before = typeof item.before_risk_score === "number" ? item.before_risk_score : undefined;
  const after = typeof item.after_risk_score === "number" ? item.after_risk_score : undefined;
  if (before === undefined || after === undefined) return "—";
  const delta = after - before;
  return delta > 0 ? `+${delta}` : String(delta);
}
