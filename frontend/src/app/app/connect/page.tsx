"use client";

import { useState } from "react";
import { CloudCog, Loader2, TerminalSquare, Save } from "lucide-react";
import { useSafeOps } from "@/components/safeops-data-provider";
import { Button, Card, PageHeader } from "@/components/safeops-ui";

export default function ConnectPage() {
  const { bundle, saveSettings, testAws, saving, testingAws } = useSafeOps();

  const [form, setForm] = useState({
    aws_region: bundle.settings?.aws_region || "us-east-1",
    role_arn: bundle.settings?.role_arn || "",
  });

  const update = (key: string, value: string) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  return (
    <div className="connect-page">
      <PageHeader
        eyebrow="AWS onboarding"
        title="Connect your AWS account"
        description="SafeOps uses read-only access to scan your cloud security posture."
      />

      <Card className="connect-card">
        <CloudCog className="h-6 w-6 text-cyan-200" />

        <h2>Step 1: Provide AWS access</h2>

        <p>
          Enter your AWS region and optional role ARN. SafeOps will use this to scan your cloud securely.
        </p>

        <label>
          <span>AWS Region</span>
          <input
            value={form.aws_region}
            onChange={(e) => update("aws_region", e.target.value)}
          />
        </label>

        <label>
          <span>Role ARN (optional)</span>
          <input
            value={form.role_arn}
            onChange={(e) => update("role_arn", e.target.value)}
            placeholder="arn:aws:iam::123456789012:role/SafeOpsReadOnly"
          />
        </label>

        <div className="connect-actions">
          <Button onClick={() => saveSettings(form)} disabled={saving}>
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Save settings
          </Button>

          <Button variant="secondary" onClick={testAws} disabled={testingAws}>
            {testingAws ? <Loader2 className="h-4 w-4 animate-spin" /> : <TerminalSquare className="h-4 w-4" />}
            Test connection
          </Button>
        </div>
      </Card>
    </div>
  );
}