def classify_fix(finding):
    fingerprint = finding.fingerprint if hasattr(finding, "fingerprint") else finding.get("fingerprint", "")
    severity = finding.severity if hasattr(finding, "severity") else finding.get("severity", "unknown")

    if "AWS_SECURITY_GROUP_PUBLIC_PORT" in fingerprint:
        return {
            "category": "auto_fix_now",
            "can_auto_fix": True,
            "reason": "Public admin/database port exposure is high-risk and usually safe to remove automatically.",
            "recommended_action": "Remove public ingress rule.",
        }

    if "S3_PUBLIC_BUCKET" in fingerprint:
        return {
            "category": "review_before_fix",
            "can_auto_fix": True,
            "reason": "Public S3 access may be intentional for websites or public assets, so review is recommended before blocking access.",
            "recommended_action": "Review bucket purpose, then block public access if unintended.",
        }

    if "AWS_RDS_PUBLIC_INSTANCE" in fingerprint:
        return {
            "category": "review_before_fix",
            "can_auto_fix": True,
            "reason": "Disabling public RDS access is recommended, but it can disrupt external applications.",
            "recommended_action": "Confirm network dependencies, then disable public accessibility.",
        }

    if "AWS_IAM_PUBLIC_ASSUME_ROLE" in fingerprint:
        return {
            "category": "manual_only",
            "can_auto_fix": False,
            "reason": "IAM trust policy changes can break cross-account integrations and should be reviewed manually.",
            "recommended_action": "Restrict trusted principals to known AWS accounts or roles.",
        }

    if "AWS_IAM_PRIV_ESC" in fingerprint:
        return {
            "category": "manual_only",
            "can_auto_fix": False,
            "reason": "Privilege escalation permissions require least-privilege review before removal.",
            "recommended_action": "Review dangerous IAM actions and remove unnecessary privilege escalation paths.",
        }

    if "S3_SENSITIVE_OBJECT_NAMES" in fingerprint:
        return {
            "category": "manual_only",
            "can_auto_fix": False,
            "reason": "Sensitive-looking object names require human review because SafeOps does not inspect file contents.",
            "recommended_action": "Review flagged objects, restrict access, and move secrets/backups if needed.",
        }

    if "S3_POTENTIALLY_PUBLIC" in fingerprint:
        return {
            "category": "unsupported",
            "can_auto_fix": False,
            "reason": "SafeOps could not fully verify effective public access, so automatic remediation is not safe.",
            "recommended_action": "Manually review bucket policies, ACLs, and public access block settings.",
        }

    if "ATTACK_PATH" in fingerprint:
        return {
            "category": "manual_only",
            "can_auto_fix": False,
            "reason": "Attack path findings are correlated risk summaries and should be resolved by fixing the underlying findings.",
            "recommended_action": "Fix the underlying IAM, S3, network, or database findings that create this path.",
        }

    return {
        "category": "unsupported",
        "can_auto_fix": False,
        "reason": "SafeOps does not currently support automatic remediation for this finding type.",
        "recommended_action": "Review manually.",
    }