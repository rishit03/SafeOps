from safeops.cloud.aws.s3_scanner import scan_s3_public_buckets
from safeops.cloud.aws.security_groups import scan_security_groups
from safeops.cloud.aws.rds_scanner import scan_public_rds_instances
from safeops.cloud.aws.iam_scanner import scan_publicly_assumable_roles
import os

from app.database import SessionLocal
from app.models import Scan, Finding, WorkspaceSettings, Asset
from safeops.alerts.slack import send_slack_alert
from safeops.cloud.aws.iam_priv_esc_scanner import scan_iam_privilege_escalation
from safeops.cloud.aws.attack_path_scanner import detect_attack_paths
from safeops.engine.fix_prioritizer import classify_fix
from app.models import CloudAccount



def get_or_create_asset(db, cloud_account_id, asset_type, name, raw=None):
    if not name:
        return None

    asset = (
        db.query(Asset)
        .filter(
            Asset.cloud_account_id == cloud_account_id,
            Asset.asset_type == asset_type,
            Asset.name == str(name),
        )
        .first()
    )

    if asset:
        return asset

    asset = Asset(
        cloud_account_id=cloud_account_id,
        asset_id=str(name),
        asset_type=asset_type,
        name=str(name),
        raw=raw or {},
    )

    db.add(asset)
    db.flush()

    return asset


def asset_from_finding(db, account, finding):
    if not account:
        return None

    raw = finding or {}

    if raw.get("bucket_name"):
        return get_or_create_asset(
            db,
            account.id,
            "s3_bucket",
            raw.get("bucket_name"),
            raw,
        )

    if raw.get("role_name"):
        return get_or_create_asset(
            db,
            account.id,
            "iam_role",
            raw.get("role_name"),
            raw,
        )

    if raw.get("security_group_id"):
        return get_or_create_asset(
            db,
            account.id,
            "security_group",
            raw.get("security_group_id"),
            raw,
        )

    if raw.get("db_instance_identifier"):
        return get_or_create_asset(
            db,
            account.id,
            "rds_instance",
            raw.get("db_instance_identifier"),
            raw,
        )

    if raw.get("resource_id"):
        return get_or_create_asset(
            db,
            account.id,
            str(raw.get("resource_type") or "aws_resource"),
            raw.get("resource_id"),
            raw,
        )

    return None


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

            asset = asset_from_finding(db, account, f)

            db.add(
                Finding(
                    scan_id=scan.id,
                    asset_id=asset.id if asset else None,
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