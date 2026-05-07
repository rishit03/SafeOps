from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Activity, Finding, Scan, FixHistory
from app.schemas import ScanIn, ScanOut
from app.scan_engine import run_scan_and_store

from safeops.fixes.security_group_fix import fix_security_group_public_port
from safeops.fixes.s3_fix import fix_s3_public_acl
from safeops.fixes.rds_fix import fix_rds_public_instance
from safeops.fixes.iam_fix import fix_iam_public_assume_role


router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def apply_fix(issue_id: str, role_arn: str | None = None) -> bool:
    if "AWS_SECURITY_GROUP_PUBLIC_PORT" in issue_id:
        return fix_security_group_public_port(issue_id, role_arn=role_arn)

    if "S3_PUBLIC_BUCKET" in issue_id:
        return fix_s3_public_acl(issue_id, role_arn=role_arn)

    if "AWS_RDS_PUBLIC_INSTANCE" in issue_id:
        return fix_rds_public_instance(issue_id, role_arn=role_arn)

    if "AWS_IAM_PUBLIC_ASSUME_ROLE" in issue_id:
        return fix_iam_public_assume_role(issue_id, role_arn=role_arn)

    raise HTTPException(status_code=400, detail="Unsupported issue type")


def log_activity(db: Session, action: str, details: str):
    db.add(Activity(action=action, details=details))
    db.commit()


@router.post("/api/scans", response_model=ScanOut)
def create_scan(scan_in: ScanIn, db: Session = Depends(get_db)):
    scan = Scan(
        profile=scan_in.profile,
        risk_score=scan_in.risk_score,
        risk_level=scan_in.risk_level,
    )

    db.add(scan)
    db.flush()

    for finding_in in scan_in.findings:
        db.add(
            Finding(
                scan_id=scan.id,
                fingerprint=finding_in.fingerprint,
                title=finding_in.title,
                severity=finding_in.severity,
                status=finding_in.status,
                module=finding_in.module,
                remediation_priority=finding_in.remediation_priority,
                raw=finding_in.raw,
            )
        )

    db.commit()
    db.refresh(scan)
    return scan


@router.get("/api/scans/latest", response_model=ScanOut | None)
def get_latest_scan(db: Session = Depends(get_db)):
    return db.query(Scan).order_by(Scan.created_at.desc()).first()


@router.post("/api/fix")
def fix_issue(payload: dict, db: Session = Depends(get_db)):
    issue_id = payload.get("issue_id")
    all_critical = payload.get("all_critical", False)
    role_arn = payload.get("role_arn")

    try:
        latest_scan = db.query(Scan).order_by(Scan.created_at.desc()).first()
        before_score = latest_scan.risk_score if latest_scan else 0

        if all_critical:
            if not latest_scan:
                return {"success": False, "message": "No scan data available"}

            findings = (
                db.query(Finding)
                .filter(Finding.scan_id == latest_scan.id)
                .all()
            )

            applied = 0

            for finding in findings:
                if finding.severity not in ["critical", "high"]:
                    continue

                success = apply_fix(finding.fingerprint, role_arn=role_arn)

                if success:
                    applied += 1
                    db.add(Activity(
                        action="fix",
                        details=f"Fixed {finding.title}"
                    ))

                    result = run_scan_and_store()
                    after_scan = db.query(Scan).order_by(Scan.created_at.desc()).first()
                    after_score = after_scan.risk_score if after_scan else before_score

                    db.add(FixHistory(
                        issue_id=finding.fingerprint,
                        title=finding.title,
                        severity=finding.severity,
                        status="success",
                        message="Fix applied successfully",
                        before_risk_score=before_score,
                        after_risk_score=after_score,
                    ))

                    before_score = after_score

                else:
                    db.add(FixHistory(
                        issue_id=finding.fingerprint,
                        title=finding.title,
                        severity=finding.severity,
                        status="failed",
                        message="Fix failed or not applied",
                        before_risk_score=before_score,
                        after_risk_score=before_score,
                    ))

            db.commit()

            if applied == 0:
                result = run_scan_and_store()
                raise HTTPException(
                    status_code=400,
                    detail=f"No supported fixes were applied. Scan refreshed ({result['findings']} findings remaining)."
                )

            result = run_scan_and_store()

            return {
                "success": True,
                "message": (
                    f"Applied {applied} high-signal fixes and refreshed scan "
                    f"({result['findings']} findings remaining)"
                ),
            }

        if not issue_id:
            raise HTTPException(status_code=400, detail="issue_id required")

        matched = None

        if latest_scan:
            matched = (
                db.query(Finding)
                .filter(Finding.scan_id == latest_scan.id)
                .filter(Finding.fingerprint == issue_id)
                .first()
            )

        success = apply_fix(issue_id, role_arn=role_arn)

        if success:
            db.add(Activity(
                action="fix",
                details=f"Fixed {matched.title if matched else issue_id}"
            ))

            result = run_scan_and_store()

            after_scan = db.query(Scan).order_by(Scan.created_at.desc()).first()
            after_score = after_scan.risk_score if after_scan else before_score

            db.add(FixHistory(
                issue_id=issue_id,
                title=matched.title if matched else issue_id,
                severity=matched.severity if matched else "unknown",
                status="success",
                message="Fix applied successfully",
                before_risk_score=before_score,
                after_risk_score=after_score,
            ))

            db.commit()

            return {
                "success": True,
                "message": (
                    f"Fix applied and scan refreshed "
                    f"({result['findings']} findings remaining)"
                ),
            }

        db.add(FixHistory(
            issue_id=issue_id,
            title=matched.title if matched else issue_id,
            severity=matched.severity if matched else "unknown",
            status="failed",
            message="Fix failed or not applied",
            before_risk_score=before_score,
            after_risk_score=before_score,
        ))
        db.commit()

        raise HTTPException(
            status_code=400,
            detail="Fix failed or the issue may already be resolved. Run Scan to refresh dashboard state."
        )

    except HTTPException:
        raise
    except Exception as e:
        print("FIX ERROR:", repr(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/scan/run")
def run_scan(db: Session = Depends(get_db)):
    try:
        result = run_scan_and_store()

        log_activity(
            db,
            "scan",
            f"manual scan completed ({result['findings']} findings)",
        )

        return {
            "success": True,
            "message": "Scan completed successfully",
        }

    except Exception as e:
        print("SCAN RUN ERROR:", repr(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/activity")
def get_activity(db: Session = Depends(get_db)):
    return (
        db.query(Activity)
        .order_by(Activity.created_at.desc())
        .limit(10)
        .all()
    )


@router.get("/api/scans/history")
def get_scan_history(db: Session = Depends(get_db)):
    scans = (
        db.query(Scan)
        .order_by(Scan.created_at.asc())
        .limit(20)
        .all()
    )

    return [
        {
            "id": scan.id,
            "risk_score": scan.risk_score,
            "risk_level": scan.risk_level,
            "created_at": scan.created_at.isoformat(),
        }
        for scan in scans
    ]

@router.get("/api/settings")
def get_settings(db: Session = Depends(get_db)):
    from app.models import WorkspaceSettings

    settings = db.query(WorkspaceSettings).first()

    if not settings:
        settings = WorkspaceSettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)

    return settings


@router.post("/api/settings")
def update_settings(payload: dict, db: Session = Depends(get_db)):
    from app.models import WorkspaceSettings

    settings = db.query(WorkspaceSettings).first()

    if not settings:
        settings = WorkspaceSettings()
        db.add(settings)
        db.flush()

    settings.aws_region = payload.get("aws_region", settings.aws_region)
    settings.role_arn = payload.get("role_arn", settings.role_arn)
    settings.slack_webhook_url = payload.get(
        "slack_webhook_url",
        settings.slack_webhook_url,
    )
    settings.scan_frequency_minutes = payload.get(
        "scan_frequency_minutes",
        settings.scan_frequency_minutes,
    )

    db.commit()
    db.refresh(settings)

    return {
        "success": True,
        "message": "Settings updated",
        "settings": settings,
    }

@router.post("/api/settings/test-aws")
def test_aws_connection(db: Session = Depends(get_db)):
    import boto3
    from app.models import WorkspaceSettings

    settings = db.query(WorkspaceSettings).first()

    try:
        session = boto3.Session(region_name=settings.aws_region if settings else "us-east-1")

        if settings and settings.role_arn:
            sts = session.client("sts")
            assumed = sts.assume_role(
                RoleArn=settings.role_arn,
                RoleSessionName="safeops-test-session",
            )

            creds = assumed["Credentials"]

            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=settings.aws_region,
            )

        identity = session.client("sts").get_caller_identity()

        return {
            "success": True,
            "message": "AWS connection successful",
            "account_id": identity.get("Account"),
            "arn": identity.get("Arn"),
        }

    except Exception as e:
        return {
            "success": False,
            "message": str(e),
        }
    
@router.get("/api/fix-history")
def get_fix_history(db: Session = Depends(get_db)):
    return (
        db.query(FixHistory)
        .order_by(FixHistory.created_at.desc())
        .limit(20)
        .all()
    )