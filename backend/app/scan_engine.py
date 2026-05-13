from safeops.cloud.aws.s3_scanner import scan_s3_public_buckets
from safeops.cloud.aws.security_groups import scan_security_groups
from safeops.cloud.aws.rds_scanner import scan_public_rds_instances
from safeops.cloud.aws.iam_scanner import scan_publicly_assumable_roles
import os

from app.database import SessionLocal
from app.models import Scan, Finding, WorkspaceSettings
from safeops.alerts.slack import send_slack_alert
from safeops.cloud.aws.iam_priv_esc_scanner import scan_iam_privilege_escalation
from safeops.cloud.aws.attack_path_scanner import detect_attack_paths
from safeops.engine.fix_prioritizer import classify_fix
from app.models import CloudAccount



def run_scan_and_store(account_id=None):
    db = SessionLocal()

    try:
        settings = db.query(WorkspaceSettings).first()

        if account_id:
            account = db.query(CloudAccount).filter(CloudAccount.id == account_id).first()
        else:
            account = db.query(CloudAccount).filter(CloudAccount.is_default == True).first()

        profile = None
        role_arn = account.role_arn if account and account.role_arn else None

        all_findings = []

        s3 = scan_s3_public_buckets(profile=profile, role_arn=role_arn)
        sg = scan_security_groups(profile=profile, role_arn=role_arn)
        rds = scan_public_rds_instances(profile=profile, role_arn=role_arn)
        iam = scan_publicly_assumable_roles(profile=profile, role_arn=role_arn)
        iam_priv = scan_iam_privilege_escalation(profile=profile, role_arn=role_arn)

        for result in [s3, sg, rds, iam, iam_priv]:

            if result.get("status") == "success":

                all_findings.extend(result.get("findings", []))

            else:

                print("SCAN MODULE ERROR:", result.get("module"), result.get("error"))
        
        attack_paths = detect_attack_paths(all_findings)

        all_findings.extend(attack_paths)

        webhook_url = settings.slack_webhook_url if settings else None

        if not webhook_url:
            webhook_url = os.getenv("SLACK_WEBHOOK_URL")

        if webhook_url:
            critical_findings = [
                f for f in all_findings if f.get("severity") == "critical"
            ]

            if critical_findings:
                send_slack_alert(
                    webhook_url,
                    f"🚨 SafeOps Alert: {len(critical_findings)} critical issues detected in {account.name if account else 'AWS'}",
                )

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

        scan = Scan(
            profile="default",
            risk_score=risk_score,
            risk_level=risk_level,
            cloud_account_id=account.id if account else None,
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
            
            fix_priority = classify_fix(f)

            f["fix_priority"] = fix_priority["category"]
            f["can_auto_fix"] = fix_priority["can_auto_fix"]
            f["fix_reason"] = fix_priority["reason"]
            f["recommended_action"] = fix_priority["recommended_action"]

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

    finally:
        db.close()