from safeops.cloud.aws.s3_scanner import scan_s3_public_buckets
from safeops.cloud.aws.security_groups import scan_security_groups
from safeops.cloud.aws.rds_scanner import scan_public_rds_instances
from safeops.cloud.aws.iam_scanner import scan_publicly_assumable_roles

from app.database import SessionLocal
from app.models import Scan, Finding
from safeops.alerts.slack import send_slack_alert


def run_scan_and_store():
    profile = None
    role_arn = None

    all_findings = []

    s3 = scan_s3_public_buckets(profile=profile, role_arn=role_arn)
    sg = scan_security_groups(profile=profile, role_arn=role_arn)
    rds = scan_public_rds_instances(profile=profile, role_arn=role_arn)
    iam = scan_publicly_assumable_roles(profile=profile, role_arn=role_arn)

    for result in [s3, sg, rds, iam]:
        if result["status"] == "success":
            all_findings.extend(result.get("findings", []))
    
    from app.database import SessionLocal
    from app.models import WorkspaceSettings

    db = SessionLocal()
    settings = db.query(WorkspaceSettings).first()

    if settings and settings.slack_webhook_url:
        critical_findings = [f for f in all_findings if f.get("severity") == "critical"]

        if critical_findings:
            send_slack_alert(
                settings.slack_webhook_url,
                f"🚨 SafeOps Alert: {len(critical_findings)} critical issues detected in AWS"
            )

    # simple risk score
    risk_score = 0

    for f in all_findings:
        severity = f.get("severity")
        if severity == "critical":
            risk_score += 40
        elif severity == "high":
            risk_score += 20

    risk_score = min(risk_score, 100)

    if risk_score >= 80:
        risk_level = "Critical"
    elif risk_score >= 50:
        risk_level = "High"
    elif risk_score >= 20:
        risk_level = "Moderate"
    else:
        risk_level = "Low"

    db = SessionLocal()

    scan = Scan(
        profile="default",
        risk_score=risk_score,
        risk_level=risk_level,
    )

    db.add(scan)
    db.flush()

    for f in all_findings:

        fingerprint = f.get("fingerprint", "")
        if not fingerprint.startswith("default:"):
            fingerprint = f"default:{fingerprint}"
        title = f.get("title", "Unknown finding")
        if not title.startswith("[default]"):
            title = f"[default] {title}"
        db.add(
            Finding(
                scan_id=scan.id,
                fingerprint=fingerprint,
                title=title,
                severity=f.get("severity"),
                status="new",
                module=f.get("module"),
                remediation_priority=f.get("remediation_priority"),
                raw=f,
            )
        )

    db.commit()

    return {"risk_score": risk_score, "findings": len(all_findings)}