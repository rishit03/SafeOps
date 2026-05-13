import Link from "next/link";
import { ShieldCheck, Zap, AlertTriangle, GitBranch } from "lucide-react";

export default function LandingPage() {
  return (
    <main className="landing">
      <section className="landing-hero">
        <p className="eyebrow">SafeOps</p>

        <h1>
          Find and fix AWS security risks
          <br />
          before they become incidents
        </h1>

        <p>
          SafeOps scans your cloud, prioritizes real risks, and helps you fix them safely.
          Built for startups that need security without complexity.
        </p>

        <div className="landing-actions">
          <Link href="/login" className="safeops-button safeops-button-primary">
            Get started
          </Link>

          <Link href="/app" className="safeops-button safeops-button-secondary">
            View dashboard
          </Link>
        </div>
      </section>

      <section className="landing-features">
        <Feature
          icon={<AlertTriangle />}
          title="Detect real risks"
          text="Find exposed ports, public data, and IAM privilege escalation issues."
        />

        <Feature
          icon={<GitBranch />}
          title="Understand attack paths"
          text="See how individual misconfigurations combine into real compromise paths."
        />

        <Feature
          icon={<Zap />}
          title="Fix safely"
          text="Automatically fix low-risk issues and guide manual remediation for critical ones."
        />

        <Feature
          icon={<ShieldCheck />}
          title="Stay secure"
          text="Track risk score, audit fixes, and monitor your cloud continuously."
        />
      </section>
    </main>
  );
}

function Feature({ icon, title, text }: any) {
  return (
    <div className="landing-feature">
      <div className="feature-icon">{icon}</div>
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}