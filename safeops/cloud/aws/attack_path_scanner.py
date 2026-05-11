def detect_attack_paths(findings):
    attack_findings = []

    has_priv_esc = any(
        "AWS_IAM_PRIV_ESC" in f.get("fingerprint", "")
        for f in findings
    )

    public_s3 = [
        f for f in findings
        if "S3_PUBLIC_BUCKET" in f.get("fingerprint", "")
    ]

    sensitive_s3 = [
        f for f in findings
        if "S3_SENSITIVE_OBJECT_NAMES" in f.get("fingerprint", "")
    ]

    if has_priv_esc and (public_s3 or sensitive_s3):
        attack_findings.append({
            "fingerprint": "ATTACK_PATH:IAM+S3",
            "title": "Attack path: IAM privilege escalation + exposed S3 data",
            "severity": "critical",
            "module": "attack_paths",
            "remediation_priority": "Fix now",
            "why_it_matters": (
                "An attacker could escalate privileges and access sensitive S3 data, "
                "leading to full data exfiltration."
            ),
        })

    return attack_findings