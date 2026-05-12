"use client";

import { useMemo, useState, type ComponentType } from "react";
import {
  Activity,
  AlertCircle,
  ArrowDownRight,
  Boxes,
  CheckCircle2,
  ClipboardList,
  CloudCog,
  Database,
  FileClock,
  GitBranch,
  History,
  KeyRound,
  Loader2,
  LockKeyhole,
  MessageSquare,
  RadioTower,
  RefreshCw,
  Route,
  Save,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  TrendingDown,
  Wrench,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { ActivityItem, Finding, FixHistoryItem, NavKey, Settings } from "@/lib/types";
import {
  canAutoFix,
  cx,
  findingFingerprint,
  fixPriorityLabel,
  fixPriorityTone,
  formatUserDateTime,
  getRiskLevel,
  highSignalFindings,
  riskDelta,
  riskTone,
  scanTimestamp,
  severityTone,
  shortTime,
  sortFindings,
} from "@/lib/helpers";
import { useSafeOps } from "./safeops-data-provider";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorBanner,
  LoadingScreen,
  MetricTile,
  PageHeader,
  PlannedPanel,
  SafeOpsShell,
} from "./safeops-ui";

function Frame({ active, children }: { active: NavKey; children: React.ReactNode }) {
  const { bundle, loading, refreshing, scanning, fixingAll, refresh, runScan } = useSafeOps();
  if (loading) return <LoadingScreen />;
  const firstError = Object.values(bundle.errors).filter(Boolean)[0];

  return (
    <SafeOpsShell bundle={bundle} active={active}>
      {(scanning || fixingAll) ? <OperationOverlay label={scanning ? "Scanning AWS" : "Applying fixes"} /> : null}
      <div className="action-strip">
        <ErrorBanner message={firstError} />
        <div className="action-strip-buttons">
          <Button variant="secondary" onClick={refresh} disabled={refreshing}>
            {refreshing ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Refresh
          </Button>
          <Button onClick={runScan} disabled={scanning}>
            {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <RadioTower className="h-4 w-4" />} Run scan
          </Button>
        </div>
      </div>
      {children}
    </SafeOpsShell>
  );
}

function OperationOverlay({ label }: { label: string }) {
  return (
    <div className="operation-overlay">
      <div className="operation-card">
        <div className="loading-orb small"><Loader2 className="h-6 w-6 animate-spin" /></div>
        <div><p className="eyebrow">Operation active</p><h2>{label}</h2><p>SafeOps will refresh posture data when the backend finishes.</p></div>
      </div>
    </div>
  );
}

function FindingTitle({ finding }: { finding: Finding }) {
  return <>{finding.title || finding.id || finding.fingerprint || "Untitled finding"}</>;
}

function FindingMeta({ finding }: { finding: Finding }) {
  const resource = finding.raw?.bucket_name || finding.raw?.role_name || finding.raw?.resource_type || finding.module || "AWS resource";
  return <>{String(resource)}</>;
}

function FindingRow({ finding, compact = false }: { finding: Finding; compact?: boolean }) {
  const { fixFinding, fixingOne } = useSafeOps();
  const fingerprint = String(findingFingerprint(finding));
  const fixable = canAutoFix(finding);
  const busy = fixingOne === fingerprint;

  return (
    <Card className={cx("finding-row", compact && "finding-row-compact")}>
      <div className={cx("priority-strip", fixPriorityTone(finding.raw?.fix_priority))} />
      <div className="finding-main">
        <div className="finding-leading">
          <Badge tone={severityTone(finding.severity)}>{finding.severity || "unknown"}</Badge>
          <Badge tone={fixPriorityTone(finding.raw?.fix_priority)}>{fixPriorityLabel(finding.raw?.fix_priority)}</Badge>
        </div>
        <h3><FindingTitle finding={finding} /></h3>
        <p><FindingMeta finding={finding} /></p>
        {!compact && finding.raw?.why_it_matters ? <small>{finding.raw.why_it_matters}</small> : null}
        {!compact && finding.raw?.recommended_action ? (
          <small className="finding-recommended-action">
            Action: {finding.raw.recommended_action}
          </small>
        ) : null}
      </div>
      <div className="finding-action">
        <Button variant={fixable ? "primary" : "secondary"} disabled={!fixable || busy} onClick={() => fixFinding(finding)}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wrench className="h-4 w-4" />}
          {fixable ? "Fix" : "Review"}
        </Button>
      </div>
    </Card>
  );
}

function RiskChart() {
  const { bundle } = useSafeOps();
  const data = [...bundle.history]
    .slice(-12)
    .map((scan, index) => ({
      name: shortTime(scanTimestamp(scan)) || `Scan ${index + 1}`,
      risk: scan.risk_score ?? 0,
    }));

  if (!data.length) {
    return <EmptyState icon={History} title="No trend yet" description="Run scans over time to build a risk-score timeline." />;
  }

  return (
    <div className="chart-shell">
      <ResponsiveContainer width="100%" height={260}>
        <AreaChart data={data} margin={{ top: 12, right: 12, bottom: 0, left: -18 }}>
          <defs>
            <linearGradient id="safeopsRisk" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#67e8f9" stopOpacity={0.5} />
              <stop offset="95%" stopColor="#67e8f9" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(148,163,184,0.14)" vertical={false} />
          <XAxis dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} domain={[0, 100]} />
          <Tooltip contentStyle={{ background: "#07101a", border: "1px solid rgba(103,232,249,.22)", borderRadius: 16, color: "#e5edf6" }} />
          <Area type="monotone" dataKey="risk" stroke="#67e8f9" strokeWidth={3} fill="url(#safeopsRisk)" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function OverviewPage() {
  const { bundle, fixCritical, fixingAll } = useSafeOps();
  const scan = bundle.latest;
  const findings = scan?.findings || [];
  const critical = findings.filter((finding) => String(finding.severity).toLowerCase() === "critical").length;
  const high = findings.filter((finding) => String(finding.severity).toLowerCase() === "high").length;
  const autoFixable = findings.filter(canAutoFix).length;
  const riskLevel = getRiskLevel(scan);
  const lastScan = scanTimestamp(scan);
  const topFindings = highSignalFindings(findings).slice(0, 4);

  return (
    <Frame active="overview">
      <PageHeader eyebrow="Overview" title="Cloud posture, simplified." description="A calm operating view for the risks that need action now." />
      <section className="hero-grid">
        <Card className="hero-panel">
          <div className="hero-copy">
            <Badge tone="tone-cyan"><Sparkles className="h-3.5 w-3.5" /> Production cockpit</Badge>
            <h2>{scan ? `${scan.risk_score ?? "—"}/100` : "Run your first scan"}</h2>
            <p>{scan ? "Current AWS risk score across high-signal exposure checks." : "Connect AWS settings, run a scan, and SafeOps will organize findings by urgency."}</p>
            <div className="hero-actions">
              <Button onClick={fixCritical} disabled={fixingAll || critical === 0}><Wrench className="h-4 w-4" /> Fix critical</Button>
              <Badge tone={riskTone(riskLevel)}>{riskLevel}</Badge>
            </div>
          </div>
          <div className="risk-orbit" aria-hidden="true"><span>{scan?.risk_score ?? "—"}</span></div>
        </Card>
        <div className="metric-grid">
          <MetricTile label="Critical" value={critical} detail="Needs immediate attention" icon={ShieldAlert} tone="red" />
          <MetricTile label="High" value={high} detail="Prioritized exposure" icon={AlertCircle} tone="amber" />
          <MetricTile label="Auto-fix" value={autoFixable} detail="Backend-supported" icon={Wrench} tone="green" />
          <MetricTile label="Last scan" value={lastScan ? shortTime(lastScan) : "—"} detail={lastScan ? formatUserDateTime(lastScan) : "No scan yet"} icon={History} tone="cyan" />
        </div>
      </section>
      <section className="metric-grid">
        <MetricTile
          label="Auto-fix now"
          value={findings.filter(f => f.raw?.fix_priority === "auto_fix_now").length}
          detail="Safe to fix immediately"
          icon={Wrench}
          tone="green"
        />

        <MetricTile
          label="Review needed"
          value={findings.filter(f => f.raw?.fix_priority === "review_before_fix").length}
          detail="Needs confirmation"
          icon={AlertCircle}
          tone="amber"
        />

        <MetricTile
          label="Manual only"
          value={findings.filter(f => f.raw?.fix_priority === "manual_only").length}
          detail="Human decision required"
          icon={ClipboardList}
          tone="slate"
        />

        <MetricTile
          label="Unsupported"
          value={findings.filter(f => f.raw?.fix_priority === "unsupported").length}
          detail="No auto remediation"
          icon={ShieldAlert}
          tone="red"
        />
      </section>
      <section className="two-column">
        <Card>
          <div className="section-title"><div><p className="eyebrow">Top findings</p><h2>Highest signal</h2></div><Badge tone="tone-slate">{findings.length} total</Badge></div>
          <div className="stack-list">
            {topFindings.length ? topFindings.map((finding) => <FindingRow key={String(findingFingerprint(finding))} finding={finding} compact />) : <EmptyState icon={ShieldCheck} title="No urgent findings" description="Critical and high findings will appear here after scans." />}
          </div>
        </Card>
        <Card>
          <div className="section-title"><div><p className="eyebrow">Trend</p><h2>Risk over time</h2></div><Badge tone="tone-cyan"><TrendingDown className="h-3.5 w-3.5" /> Score</Badge></div>
          <RiskChart />
        </Card>
      </section>
    </Frame>
  );
}

export function FindingsPage() {
  const { bundle } = useSafeOps();
  const findings = sortFindings(bundle.latest?.findings || []);

  const auto = findings.filter((finding) => finding.raw?.fix_priority === "auto_fix_now");
  const review = findings.filter((finding) => finding.raw?.fix_priority === "review_before_fix");
  const manual = findings.filter((finding) => finding.raw?.fix_priority === "manual_only");
  const unsupported = findings.filter((finding) => finding.raw?.fix_priority === "unsupported");

  return (
    <Frame active="findings">
      <PageHeader
        eyebrow="Findings"
        title="Actionable exposure."
        description="Findings are grouped by what SafeOps can safely do next."
      />

      {findings.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          title="No findings yet"
          description="Run a scan to populate active cloud security findings."
        />
      ) : (
        <div className="stack-list">
          <Card>
            <div className="section-title">
              <div>
                <p className="eyebrow">Immediate action</p>
                <h2>Auto-fix available</h2>
              </div>
              <Badge tone="tone-green">{auto.length}</Badge>
            </div>
            <div className="stack-list">
              {auto.length ? (
                auto.map((finding) => (
                  <FindingRow key={String(findingFingerprint(finding))} finding={finding} />
                ))
              ) : (
                <EmptyState
                  icon={CheckCircle2}
                  title="No auto-fixable findings"
                  description="SafeOps will place low-risk automatic remediations here."
                />
              )}
            </div>
          </Card>

          <Card>
            <div className="section-title">
              <div>
                <p className="eyebrow">Needs confirmation</p>
                <h2>Review before fix</h2>
              </div>
              <Badge tone="tone-amber">{review.length}</Badge>
            </div>
            <div className="stack-list">
              {review.length ? (
                review.map((finding) => (
                  <FindingRow key={String(findingFingerprint(finding))} finding={finding} />
                ))
              ) : (
                <EmptyState
                  icon={AlertCircle}
                  title="No review-required findings"
                  description="Findings that may affect production behavior will appear here."
                />
              )}
            </div>
          </Card>

          <Card>
            <div className="section-title">
              <div>
                <p className="eyebrow">Human decision required</p>
                <h2>Manual only</h2>
              </div>
              <Badge tone="tone-slate">{manual.length}</Badge>
            </div>
            <div className="stack-list">
              {manual.length ? (
                manual.map((finding) => (
                  <FindingRow key={String(findingFingerprint(finding))} finding={finding} />
                ))
              ) : (
                <EmptyState
                  icon={ClipboardList}
                  title="No manual-only findings"
                  description="IAM privilege risks, sensitive data signals, and attack paths will appear here."
                />
              )}
            </div>
          </Card>

          {unsupported.length > 0 ? (
            <Card>
              <div className="section-title">
                <div>
                  <p className="eyebrow">Not automated</p>
                  <h2>Unsupported</h2>
                </div>
                <Badge tone="tone-red">{unsupported.length}</Badge>
              </div>
              <div className="stack-list">
                {unsupported.map((finding) => (
                  <FindingRow key={String(findingFingerprint(finding))} finding={finding} />
                ))}
              </div>
            </Card>
          ) : null}
        </div>
      )}
    </Frame>
  );
}

export function AttackPathsPage() {
  const { bundle } = useSafeOps();
  const findings = bundle.latest?.findings || [];

  const entryPoints = findings.filter((f) =>
    String(f.fingerprint || "").includes("SECURITY_GROUP_PUBLIC_PORT")
  );

  const privilegeEsc = findings.filter((f) =>
    String(f.fingerprint || "").includes("IAM_PRIV_ESC")
  );

  const dataExposure = findings.filter((f) =>
    String(f.fingerprint || "").includes("S3_")
  );

  return (
    <Frame active="attack-paths">
      <PageHeader
        eyebrow="Attack paths"
        title="How compromise can happen."
        description="SafeOps shows how individual risks can combine into real attack paths."
      />

      <Card>
        {entryPoints.length || privilegeEsc.length || dataExposure.length ? (
          <div className="attack-flow">
            {/* Entry */}
            <AttackColumn
              title="Entry point"
              icon={ShieldAlert}
              items={entryPoints}
            />

            {/* Arrow */}
            <AttackArrow />

            {/* Priv Esc */}
            <AttackColumn
              title="Privilege escalation"
              icon={KeyRound}
              items={privilegeEsc}
            />

            {/* Arrow */}
            <AttackArrow />

            {/* Data */}
            <AttackColumn
              title="Data exposure"
              icon={Database}
              items={dataExposure}
            />
          </div>
        ) : (
          <EmptyState
            icon={GitBranch}
            title="No attack paths detected"
            description="SafeOps will map risk chains when multiple exposures can combine into a real compromise path."
          />
        )}
      </Card>
    </Frame>
  );
}

function AttackColumn({
  title,
  icon: Icon,
  items,
}: {
  title: string;
  icon: ComponentType<{ className?: string }>;
  items: Finding[];
}) {
  return (
    <div className="attack-column">
      <div className="attack-column-header">
        <Icon className="h-5 w-5" />
        <h3>{title}</h3>
      </div>

      <div className="attack-column-list">
        {items.length ? (
          items.map((f) => (
            <div key={String(findingFingerprint(f))} className="attack-node">
              <Badge tone={severityTone(f.severity)}>
                {f.severity}
              </Badge>
              <span>{f.title}</span>
            </div>
          ))
        ) : (
          <p className="attack-empty">No signal</p>
        )}
      </div>
    </div>
  );
}

function AttackArrow() {
  return (
    <div className="attack-arrow">
      <ArrowDownRight className="h-6 w-6" />
    </div>
  );
}

export function RemediationPage() {
  const { bundle, fixCritical, fixingAll } = useSafeOps();
  const findings = sortFindings(bundle.latest?.findings || []);
  const auto = findings.filter(canAutoFix);
  const manual = findings.filter((finding) => !canAutoFix(finding));
  return (
    <Frame active="remediation">
      <PageHeader eyebrow="Remediation" title="Fix what can be fixed safely." description="Supported fixes stay one click away; manual items remain clearly marked." action={<Button onClick={fixCritical} disabled={fixingAll || !auto.length}>{fixingAll ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wrench className="h-4 w-4" />} Fix critical</Button>} />
      <section className="two-column">
        <Card><div className="section-title"><div><p className="eyebrow">Auto-fix</p><h2>Supported</h2></div><Badge tone="tone-green">{auto.length}</Badge></div><div className="stack-list">{auto.length ? auto.map((finding) => <FindingRow key={String(findingFingerprint(finding))} finding={finding} compact />) : <EmptyState icon={CheckCircle2} title="No supported fixes" description="Auto-fixable findings will appear here." />}</div></Card>
        <Card><div className="section-title"><div><p className="eyebrow">Manual</p><h2>Review queue</h2></div><Badge tone="tone-amber">{manual.length}</Badge></div><div className="stack-list">{manual.length ? manual.slice(0, 8).map((finding) => <FindingRow key={String(findingFingerprint(finding))} finding={finding} compact />) : <EmptyState icon={ClipboardList} title="Manual queue clear" description="Findings requiring review will appear here." />}</div></Card>
      </section>
    </Frame>
  );
}

export function AssetsPage() {
  const findings = useSafeOps().bundle.latest?.findings || [];
  const buckets = findings.filter((finding) => finding.raw?.bucket_name);
  const roles = findings.filter((finding) => finding.raw?.role_name);
  const other = findings.filter((finding) => !finding.raw?.bucket_name && !finding.raw?.role_name);
  return (
    <Frame active="assets">
      <PageHeader eyebrow="Assets" title="Resources under watch." description="Grouped from active findings so teams can see which assets carry risk." />
      <section className="asset-grid">
        <AssetGroup title="S3 buckets" icon={Database} findings={buckets} />
        <AssetGroup title="IAM roles" icon={KeyRound} findings={roles} />
        <AssetGroup title="Other resources" icon={Boxes} findings={other} />
      </section>
    </Frame>
  );
}

function AssetGroup({ title, icon: Icon, findings }: { title: string; icon: typeof Boxes; findings: Finding[] }) {
  return <Card><div className="section-title"><div><p className="eyebrow">Assets</p><h2>{title}</h2></div><Icon className="h-5 w-5 text-cyan-200" /></div><div className="stack-list">{findings.length ? findings.slice(0, 8).map((finding) => <div className="asset-row" key={String(findingFingerprint(finding))}><Badge tone={severityTone(finding.severity)}>{finding.severity}</Badge><span><FindingMeta finding={finding} /></span></div>) : <EmptyState icon={Icon} title="No active risks" description="Related resources will appear when findings exist." />}</div></Card>;
}

export function ActivityPage() {
  const { bundle } = useSafeOps();
  return <Frame active="activity"><TimelinePage title="Activity" eyebrow="Activity" description="Recent scan and system events." items={bundle.activity} kind="activity" /></Frame>;
}

export function AuditPage() {
  const { bundle } = useSafeOps();
  return <Frame active="audit"><TimelinePage title="Fix audit trail" eyebrow="Audit" description="Remediation history with before and after risk deltas." items={bundle.fixHistory} kind="audit" /></Frame>;
}

function TimelinePage({ title, eyebrow, description, items, kind }: { title: string; eyebrow: string; description: string; items: Array<ActivityItem | FixHistoryItem>; kind: "activity" | "audit" }) {
  return (
    <>
      <PageHeader eyebrow={eyebrow} title={title} description={description} />
      <Card>
        <div className="timeline">
          {items.length ? items.map((item, index) => (
            <div className="timeline-item" key={String(item.id || item.created_at || item.timestamp || index)}>
              <div className="timeline-dot"><Activity className="h-3.5 w-3.5" /></div>
              <div>
                <h3>{String(item.message || item.title || item.action || item.type || "SafeOps event")}</h3>
                <p>{formatUserDateTime(item.created_at || item.timestamp)}</p>
              </div>
              {kind === "audit" ? <Badge tone={String((item as FixHistoryItem).status).includes("success") ? "tone-green" : "tone-slate"}>{riskDelta(item as FixHistoryItem)}</Badge> : <Badge tone="tone-cyan">{String(item.status || item.type || "event")}</Badge>}
            </div>
          )) : <EmptyState icon={kind === "audit" ? FileClock : Activity} title={`No ${title.toLowerCase()} yet`} description="Events will appear here once SafeOps has data from the backend." />}
        </div>
      </Card>
    </>
  );
}

export function IntegrationsPage() {
  const { bundle, testAws, testingAws } = useSafeOps();
  const settings = bundle.settings;
  const awsReady = Boolean(settings?.role_arn || settings?.aws_connected);
  const slackReady = Boolean(settings?.slack_webhook_url || settings?.slack_configured);
  return (
    <Frame active="integrations">
      <PageHeader eyebrow="Integrations" title="Connect the essentials." description="AWS provides posture data. Slack delivers alerts." />
      <section className="two-column">
        <Card className="integration-card"><CloudCog className="integration-icon" /><Badge tone={awsReady ? "tone-green" : "tone-amber"}>{awsReady ? "Connected" : "Setup needed"}</Badge><h2>AWS account</h2><p>{settings?.role_arn ? String(settings.role_arn) : "Add a role ARN in settings, then test the connection."}</p><Button variant="secondary" onClick={testAws} disabled={testingAws}>{testingAws ? <Loader2 className="h-4 w-4 animate-spin" /> : <TerminalSquare className="h-4 w-4" />} Test AWS</Button></Card>
        <Card className="integration-card"><MessageSquare className="integration-icon" /><Badge tone={slackReady ? "tone-green" : "tone-slate"}>{slackReady ? "Enabled" : "Optional"}</Badge><h2>Slack alerts</h2><p>{settings?.slack_webhook_url ? "Webhook configured for notifications." : "Paste a Slack webhook in settings to receive scan alerts."}</p></Card>
      </section>
    </Frame>
  );
}

export function SettingsPage() {
  const { bundle, saveSettings, saving, testAws, testingAws } = useSafeOps();
  const [form, setForm] = useState<Settings>(() => bundle.settings || {});
  const update = (key: keyof Settings, value: string | number | boolean) => setForm((current) => ({ ...current, [key]: value }));

  return (
    <Frame active="settings">
      <PageHeader eyebrow="Settings" title="Operational controls." description="Keep configuration short, clear, and testable." />
      <Card className="settings-card">
        <label><span>AWS region</span><input value={String(form.aws_region || form.region || "us-east-1")} onChange={(event) => update("aws_region", event.target.value)} /></label>
        <label><span>Role ARN</span><input value={String(form.role_arn || "")} onChange={(event) => update("role_arn", event.target.value)} placeholder="arn:aws:iam::123456789012:role/SafeOpsReadOnly" /></label>
        <label><span>Scan frequency</span><input type="number" min={15} value={Number(form.scan_frequency_minutes || form.scheduled_scan_frequency_minutes || 60)} onChange={(event) => update("scan_frequency_minutes", Number(event.target.value))} /></label>
        <label><span>Slack webhook</span><input value={String(form.slack_webhook_url || "")} onChange={(event) => update("slack_webhook_url", event.target.value)} placeholder="https://hooks.slack.com/services/..." /></label>
        <div className="settings-actions"><Button onClick={() => saveSettings(form)} disabled={saving}>{saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save</Button><Button variant="secondary" onClick={testAws} disabled={testingAws}>{testingAws ? <Loader2 className="h-4 w-4 animate-spin" /> : <CloudCog className="h-4 w-4" />} Test AWS</Button></div>
      </Card>
    </Frame>
  );
}

export function PlannedPage() {
  return (
    <Frame active="planned">
      <PageHeader eyebrow="Roadmap" title="Planned surfaces." description="Visible product direction without fake backend behavior." />
      <section className="asset-grid">
        <PlannedPanel title="Policy simulator">Preview how remediation changes reduce exposure before execution.</PlannedPanel>
        <PlannedPanel title="Team workflow">Assign findings, add owners, and track due dates.</PlannedPanel>
        <PlannedPanel title="Compliance packs">Map SafeOps findings to startup security checklists.</PlannedPanel>
      </section>
    </Frame>
  );
}
