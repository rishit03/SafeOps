"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ComponentType, ReactNode } from "react";
import {
  Activity,
  Boxes,
  ChevronRight,
  ClipboardCheck,
  CloudCog,
  FileClock,
  GitBranch,
  Gauge,
  LifeBuoy,
  MessageSquare,
  Radar,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Wrench,
} from "lucide-react";
import type { ApiBundle, NavKey, Settings } from "@/lib/types";
import { cx, isValidSlackWebhook } from "@/lib/helpers";
import { signOut } from "next-auth/react";
import { useSafeOps } from "./safeops-data-provider";

export const NAV_ITEMS: Array<{ key: NavKey; href: string; label: string; icon: ComponentType<{ className?: string }>; planned?: boolean }> = [
  { key: "overview", href: "/app", label: "Overview", icon: Gauge },
  { key: "findings", href: "/app/findings", label: "Findings", icon: ShieldAlert },
  { key: "attack-paths", href: "/app/attack-paths", label: "Attack paths", icon: GitBranch },
  { key: "remediation", href: "/app/remediation", label: "Remediation", icon: Wrench },
  { key: "assets", href: "/app/assets", label: "Assets", icon: Boxes },
  { key: "activity", href: "/app/activity", label: "Activity", icon: Activity },
  { key: "audit", href: "/app/audit", label: "Audit", icon: FileClock },
  { key: "integrations", href: "/app/integrations", label: "Integrations", icon: CloudCog },
  { key: "settings", href: "/app/settings", label: "Settings", icon: Settings2 },
  { key: "planned", href: "/app/planned", label: "Roadmap", icon: Sparkles, planned: true },
  { key: "connect", href: "/app/connect", label: "Connect AWS", icon: CloudCog },
];

export function Badge({ children, tone = "tone-slate", className }: { children: ReactNode; tone?: string; className?: string }) {
  return <span className={cx("safeops-badge", tone, className)}>{children}</span>;
}

export function Button({
  children,
  variant = "primary",
  className,
  asChild,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger" | "ghost";
  asChild?: boolean;
}) {
  if (asChild) {
    return (
      <span className={cx("safeops-button", `safeops-button-${variant}`, className)}>
        {children}
      </span>
    );
  }

  return (
    <button className={cx("safeops-button", `safeops-button-${variant}`, className)} {...props}>
      {children}
    </button>
  );
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <section className={cx("safeops-card", className)}>{children}</section>;
}

export function PageHeader({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="page-header">
      <div>
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
        <h1>{title}</h1>
        {description ? <p>{description}</p> : null}
      </div>
      {action ? <div className="page-header-action">{action}</div> : null}
    </div>
  );
}

export function EmptyState({ icon: Icon = ShieldCheck, title, description, action }: { icon?: ComponentType<{ className?: string }>; title: string; description: string; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <div className="empty-state-icon"><Icon className="h-5 w-5" /></div>
      <h3>{title}</h3>
      <p>{description}</p>
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  );
}

export function MetricTile({ label, value, detail, icon: Icon, tone = "cyan" }: { label: string; value: ReactNode; detail?: ReactNode; icon: ComponentType<{ className?: string }>; tone?: "cyan" | "amber" | "green" | "red" | "slate" }) {
  return (
    <Card className={cx("metric-tile", `metric-${tone}`)}>
      <div>
        <p className="metric-label">{label}</p>
        <div className="metric-value">{value}</div>
        {detail ? <p className="metric-detail">{detail}</p> : null}
      </div>
      <div className="metric-icon"><Icon className="h-5 w-5" /></div>
    </Card>
  );
}

export function PlannedPanel({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <Card className="planned-panel">
      <Badge tone="tone-cyan">Planned</Badge>
      <h2>{title}</h2>
      <p>{children || "This surface is intentionally marked as planned so users can understand the product direction without mistaking it for connected backend functionality."}</p>
    </Card>
  );
}

function integrationStatus(settings?: Settings | null) {
  const awsReady = Boolean(settings?.role_arn || settings?.aws_connected);
  const slackReady = Boolean(isValidSlackWebhook(settings?.slack_webhook_url) || settings?.slack_configured);
  return { awsReady, slackReady };
}

export function SafeOpsShell({ bundle, active, children }: { bundle: ApiBundle; active: NavKey; children: ReactNode }) {
  const pathname = usePathname();
  const { awsReady, slackReady } = integrationStatus(bundle.settings);
  const activeItem = NAV_ITEMS.find((item) => item.key === active);
  const { activeAccountId, setActiveAccountId } = useSafeOps();

  return (
    <main className="safeops-root">
      <div className="ambient-grid" aria-hidden="true" />
      <aside className="safeops-sidebar">
        <Link href="/app" className="brand-lockup" aria-label="SafeOps overview">
          <span className="brand-mark"><ShieldCheck className="h-5 w-5" /></span>
          <span><strong>SafeOps</strong><small>Cloud posture</small></span>
        </Link>
        <nav className="side-nav" aria-label="Primary navigation">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const selected = pathname === item.href || active === item.key;
            return (
              <Link key={item.href} href={item.href} className={cx("side-nav-item", selected && "is-active")}>
                <span><Icon className="h-4 w-4" />{item.label}</span>
                {item.planned ? <Badge tone="tone-slate" className="text-[0.62rem]">Soon</Badge> : <ChevronRight className="h-3.5 w-3.5 side-chevron" />}
              </Link>
            );
          })}
        </nav>
        <div className="sidebar-footer">
          <div className="sidebar-status">
            <p className="eyebrow">Connections</p>

            <div className="status-row">
              <span><CloudCog className="h-4 w-4" />AWS</span>
              <Badge tone={awsReady ? "tone-green" : "tone-amber"}>
                {awsReady ? "Ready" : "Setup"}
              </Badge>
            </div>

            <div className="status-row">
              <span><MessageSquare className="h-4 w-4" />Slack</span>
              <Badge tone={slackReady ? "tone-green" : "tone-slate"}>
                {slackReady ? "On" : "Off"}
              </Badge>
            </div>
          </div>

          <div className="sidebar-logout">
            <button
              className="safeops-button safeops-button-secondary w-full"
              onClick={() => signOut({ callbackUrl: "/login" })}
            >
              Log out
            </button>
          </div>
        </div>
      </aside>
      <div className="safeops-main">
        <header className="topbar">
          <div>
            <p className="eyebrow">{activeItem?.label || "SafeOps"}</p>
            <h2>Security command center</h2>
          </div>
          <div className="topbar-right">
            <div className="account-switcher">
              <select
                value={activeAccountId || ""}
                onChange={(event) => setActiveAccountId(Number(event.target.value))}
              >
                {bundle.cloudAccounts.length ? (
                  bundle.cloudAccounts.map((account) => (
                    <option key={account.id} value={account.id}>
                      {account.name}
                    </option>
                  ))
                ) : (
                  <option value="">Default Account</option>
                )}
                <option disabled>+ Add account (soon)</option>
              </select>
            </div>
            <Badge tone="tone-cyan"><Radar className="h-3.5 w-3.5" /> Live backend</Badge>
            <Link href="/app/integrations" className="support-link"><LifeBuoy className="h-4 w-4" /> Setup</Link>
          </div>
        </header>
        <div className="content-frame">{children}</div>
      </div>
    </main>
  );
}

export function LoadingScreen() {
  return (
    <main className="loading-screen">
      <div className="loading-orb"><ShieldCheck className="h-7 w-7" /></div>
      <h1>SafeOps</h1>
      <p>Loading cloud posture.</p>
    </main>
  );
}

export function ErrorBanner({ message }: { message?: string }) {
  if (!message) return null;
  return (
    <div className="error-banner">
      <ClipboardCheck className="h-5 w-5" />
      <div><strong>API attention needed</strong><p>{message}</p></div>
    </div>
  );
}
