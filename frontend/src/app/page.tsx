import Link from "next/link";

export default function LandingPage() {
  return (
    <main className="landing">
      <section className="landing-hero">
        <p className="eyebrow">SafeOps</p>
        <h1>Secure your AWS in minutes.</h1>
        <p>
          SafeOps helps startups find, prioritize, and safely remediate AWS cloud
          security risks before they become incidents.
        </p>

        <div className="landing-actions">
          <Link href="/login" className="safeops-button safeops-button-primary">
            Get started
          </Link>

          <Link href="/app" className="safeops-button safeops-button-secondary">
            Open dashboard
          </Link>
        </div>
      </section>
    </main>
  );
}