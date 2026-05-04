# SafeOps

**Find the 1–2 AWS mistakes that can get your startup hacked — in under 2 minutes.**

> Built for startup engineers who want quick, high-signal AWS security checks without the noise.

⭐ If this saves you time or catches something important, consider starring the repo.

---

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

> Detects common high-risk exposures (not exhaustive coverage).

------------------------------------------------------------------------

## Install (1 minute)

``` bash
curl -sSL https://raw.githubusercontent.com/rishit03/SafeOps/main/install.sh | bash
```

After install, SafeOps runs a setup check automatically.

------------------------------------------------------------------------

## What it feels like

- Run one command
- See what could get you hacked today
- Fix it in minutes
- Leave it running to catch new issues

---

## Quick start

### 1. Run your first scan

``` bash
safeops cloud scan
```

### 2. Keep SafeOps monitoring for new risks

``` bash
safeops start --cloud
```

-   Runs periodically\
-   Stays quiet when nothing changes\
-   Alerts only when risk increases

### 3. Check status anytime

``` bash
safeops cloud check
```

Example output:

``` text
SAFEOPS CLOUD CHECK [default]: HIGH | score=40 | findings=1 | critical=1 | high=0 | trend=Worsened
```

------------------------------------------------------------------------

## Continuous monitoring

SafeOps is designed to be left running:

-   Detects only meaningful changes
-   Avoids noise
-   Helps you catch new risks early without constant checking

------------------------------------------------------------------------

## Slack alerts

``` bash
safeops config set slack_webhook_url <url>
```

------------------------------------------------------------------------

## Multi-profile support

``` bash
safeops cloud scan --profiles dev staging prod
```

> Note: Multi-profile scans are live only. State tracking is
> per-profile.

------------------------------------------------------------------------

## License

MIT
