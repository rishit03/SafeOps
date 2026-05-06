from safeops.cloud.aws.s3_scanner import scan_s3_public_buckets
from safeops.cloud.aws.security_groups import scan_security_groups
from safeops.cloud.aws.rds_scanner import scan_public_rds_instances
from safeops.cloud.aws.iam_scanner import scan_publicly_assumable_roles

from app.database import SessionLocal
from app.models import Scan, Finding


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

    # simple risk score
    risk_score = len(all_findings) * 20
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
        db.add(
            Finding(
                scan_id=scan.id,
                fingerprint=f["fingerprint"],
                title=f["title"],
                severity=f["severity"],
                status="new",
                module=f.get("module"),
                remediation_priority=f.get("remediation_priority"),
                raw=f,
            )
        )

    db.commit()

    return {"risk_score": risk_score, "findings": len(all_findings)}