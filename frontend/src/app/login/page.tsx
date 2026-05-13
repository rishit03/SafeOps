"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { signIn } from "next-auth/react";
import { Loader2, ShieldCheck } from "lucide-react";

function LoginForm() {
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get("callbackUrl") || "/app";

  const [email, setEmail] = useState("admin@safeops.local");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setLoading(true);

    const result = await signIn("credentials", {
      email,
      password,
      redirect: false,
      callbackUrl,
    });

    setLoading(false);

    if (result?.error) {
      setError("Invalid email or password.");
      return;
    }

    window.location.href = callbackUrl;
  }

  return (
    <section className="login-card">
      <div className="brand-mark">
        <ShieldCheck className="h-5 w-5" />
      </div>

      <p className="eyebrow">SafeOps access</p>
      <h1>Sign in to your cloud security cockpit</h1>
      <p className="login-subtitle">
        Use your SafeOps admin credentials to access findings, remediation,
        integrations, and audit history.
      </p>

      <form onSubmit={handleSubmit} className="login-form">
        <label>
          <span>Email</span>
          <input
            type="email"
            value={email}
            autoComplete="email"
            onChange={(event) => setEmail(event.target.value)}
            required
          />
        </label>

        <label>
          <span>Password</span>
          <input
            type="password"
            value={password}
            autoComplete="current-password"
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </label>

        {error ? <p className="login-error">{error}</p> : null}

        <button className="safeops-button safeops-button-primary" disabled={loading}>
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
          Sign in
        </button>
      </form>
    </section>
  );
}

export default function LoginPage() {
  return (
    <main className="login-shell">
      <Suspense fallback={<div className="login-card">Loading SafeOps...</div>}>
        <LoginForm />
      </Suspense>
    </main>
  );
}