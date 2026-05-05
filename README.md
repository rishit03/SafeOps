# SafeOps

**Find the 1–2 AWS mistakes that can get your startup hacked — in under 2 minutes.**

> Built for startup engineers who want quick, high-signal AWS security checks without the noise.

⭐ If this saves you time or catches something important, consider starring the repo.

---

## 🚀 What is SafeOps?

SafeOps is a lightweight CLI tool that:

- Detects high-risk AWS misconfigurations  
- Prioritizes what to fix first  
- Shows impact of each fix  
- Lets you fix issues in seconds  
- Automates cloud security workflows  

---

## ⚡ Why SafeOps

Most startups don’t have a security team.

Common risks:
- Public S3 buckets  
- Open security groups (0.0.0.0/0)  
- Public databases  
- Overly permissive IAM roles  

SafeOps focuses on:

👉 **High signal, low noise**  
👉 **Actionable fixes, not just alerts**

---

## 🧠 What it does

SafeOps doesn’t just scan — it **guides decisions**:

- Top Risk (what matters most)
- Fix Order (what to do first)
- Fix Groups (root cause grouping)
- Impact if fixed (risk reduction)
- Fix All summary (effort vs payoff)

---

## ⚙️ Install (1 minute)

```bash
curl -sSL https://raw.githubusercontent.com/rishit03/SafeOps/main/install.sh | bash
```

---

## ☁️ Cloud Setup (Recommended)

Enable full automation with one command:

```bash
aws cloudformation deploy \
  --template-file infra/safeops-fix-role.yaml \
  --stack-name safeops-access \
  --capabilities CAPABILITY_NAMED_IAM
```

Get your role ARN:

```bash
aws cloudformation describe-stacks \
  --stack-name safeops-access \
  --query "Stacks[0].Outputs"
```

---

## ▶️ Usage

### Scan your AWS environment

```bash
safeops cloud scan --role-arn <ROLE_ARN>
```

---

### Fix a single issue

```bash
safeops fix <ISSUE_ID> --apply --role-arn <ROLE_ARN>
```

---

### Fix all critical issues

```bash
safeops fix --all-critical --apply --role-arn <ROLE_ARN>
```

---

## 🔁 Continuous Monitoring

```bash
safeops start --cloud
```

- Runs in background  
- Alerts only on real changes  
- No noise  

---

## 🔔 Slack Alerts

```bash
safeops config set slack_webhook_url <url>
```

You’ll get:

- Only important alerts  
- Ready-to-run fix commands  

---

## 💡 What it feels like

- Run one command  
- See what can get you hacked  
- Fix it in minutes  
- Leave it running  

---

## 🔐 Security Model

SafeOps uses:

- IAM Role-based access (no long-term credentials)  
- Principle of least privilege  
- One-time setup via CloudFormation  

---

## 🧩 What makes SafeOps different

| Feature | SafeOps |
|--------|--------|
| Noise-free alerts | ✅ |
| Fix suggestions | ✅ |
| One-command fixes | ✅ |
| Impact estimation | ✅ |
| Bulk automation | ✅ |

---

## 📄 License

M