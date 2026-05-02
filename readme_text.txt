# SafeOps

**Find the 1--2 AWS mistakes that can get your startup hacked --- in
under 2 minutes.**

SafeOps is a lightweight CLI tool for backend and DevOps engineers to
quickly detect high-risk AWS misconfigurations and fix them fast.

------------------------------------------------------------------------

## Why SafeOps

Most startups don't have a security team.

Critical AWS issues like: - Public S3 buckets - Open security groups
(0.0.0.0/0) - Public databases - Overly permissive IAM roles

often go unnoticed until it's too late.

SafeOps focuses only on **high-signal risks** and tells you exactly what
to fix first.

------------------------------------------------------------------------

## What it does

SafeOps scans your AWS account and detects:

-   Public S3 buckets
-   Dangerous security group exposure
-   Public RDS instances
-   Risky IAM trust policies

It then shows: - The most critical issue (Top Risk) - Why it matters -
How to fix it - Time to fix - Priority (Fix now / Fix soon / Plan)

------------------------------------------------------------------------

## Install (1 minute)

``` bash
curl -sSL https://raw.githubusercontent.com/rishit03/SafeOps/main/install.sh | bash
```

After install, SafeOps runs a setup check automatically.

------------------------------------------------------------------------

## Quick start

### 1. Run your first scan

```bash
safeops cloud scan
```

### 2. Quick status check

``` bash
safeops cloud check
```

Example output:

``` text
SAFEOPS CLOUD CHECK [default]: HIGH | score=40 | findings=1 | critical=1 | high=0 | trend=Worsened
```

------------------------------------------------------------------------

## Continuous monitoring

Run SafeOps as a lightweight monitor:

``` bash
safeops start --cloud
```

-   Runs periodically
-   Stays quiet when nothing changes
-   Alerts only when risk increases

------------------------------------------------------------------------

## Slack alerts

Get notified only when something important changes:

``` bash
safeops config set slack_webhook_url <url>
```

------------------------------------------------------------------------

## Multi-profile support

Scan multiple AWS environments:

``` bash
safeops cloud scan --profiles dev staging prod
```

------------------------------------------------------------------------

## Example output

``` text
TOP RISK
--------
CRITICAL
- S3 bucket is publicly accessible: user-data

Why:
Public buckets can expose sensitive data to anyone on the internet.

Impact:
High risk of data breach and data leakage.

Confidence:
High

Fix:
1. Open AWS Console → S3 → user-data
2. Go to Permissions tab
3. Enable 'Block all public access'
4. Remove public policies

Time to fix: 2–5 minutes  
Priority: Fix now
```

------------------------------------------------------------------------

## Commands

``` bash
safeops cloud scan            # Full scan
safeops cloud scan --changes  # Only new/worsened issues
safeops cloud check           # One-line summary
safeops start --cloud         # Continuous monitoring
safeops doctor                # Setup check
```

------------------------------------------------------------------------

## Who this is for

-   Backend engineers
-   DevOps engineers
-   Startup teams without dedicated security

------------------------------------------------------------------------

## What SafeOps is NOT

-   Not a full security platform
-   Not a compliance tool
-   Not a noisy scanner

SafeOps is intentionally minimal: \> **Only high-risk issues, no
noise.**

------------------------------------------------------------------------

## Roadmap

Planned improvements: - Better multi-profile state tracking - Additional
high-signal AWS checks - Improved onboarding and UX

------------------------------------------------------------------------

## License

MIT
