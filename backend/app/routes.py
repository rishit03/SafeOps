from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Scan, Finding
from app.schemas import ScanIn, ScanOut
from fastapi import HTTPException
from safeops.fixes.security_group_fix import fix_security_group_public_port
from safeops.fixes.s3_fix import fix_s3_public_acl
from safeops.fixes.rds_fix import fix_rds_public_instance
from safeops.fixes.iam_fix import fix_iam_public_assume_role
import os
import subprocess


router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


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
        finding = Finding(
            scan_id=scan.id,
            fingerprint=finding_in.fingerprint,
            title=finding_in.title,
            severity=finding_in.severity,
            status=finding_in.status,
            module=finding_in.module,
            remediation_priority=finding_in.remediation_priority,
            raw=finding_in.raw,
        )
        db.add(finding)

    db.commit()
    db.refresh(scan)
    return scan


@router.get("/api/scans/latest", response_model=ScanOut | None)
def get_latest_scan(db: Session = Depends(get_db)):
    return db.query(Scan).order_by(Scan.created_at.desc()).first()

@router.post("/api/fix")

def fix_issue(payload: dict):

    issue_id = payload.get("issue_id")
    all_critical = payload.get("all_critical", False)
    role_arn = payload.get("role_arn")

    if all_critical:
        from app.database import SessionLocal
        from app.models import Scan, Finding

        db = SessionLocal()

        latest_scan = db.query(Scan).order_by(Scan.created_at.desc()).first()

        if not latest_scan:
            return {"success": False, "message": "No scan data available"}

        findings = db.query(Finding).filter(Finding.scan_id == latest_scan.id).all()

        applied = 0

        for f in findings:
            if f.severity not in ["critical", "high"]:
                continue

            issue_id = f.fingerprint

            if issue_id.startswith("default:AWS_SECURITY_GROUP_PUBLIC_PORT"):
                success = fix_security_group_public_port(issue_id, role_arn=role_arn)

            elif issue_id.startswith("default:S3_PUBLIC_BUCKET"):
                success = fix_s3_public_acl(issue_id, role_arn=role_arn)

            elif issue_id.startswith("default:AWS_RDS_PUBLIC_INSTANCE"):
                success = fix_rds_public_instance(issue_id, role_arn=role_arn)

            elif issue_id.startswith("default:AWS_IAM_PUBLIC_ASSUME_ROLE"):
                success = fix_iam_public_assume_role(issue_id, role_arn=role_arn)

            else:
                success = False

            if success:
                from app.models import Activity
                from app.database import SessionLocal
                db = SessionLocal()
                db.add(Activity(
                    action="fix",
                    details=issue_id
                ))
                db.commit()
                applied += 1

        try:
            env = os.environ.copy()
            env["SAFEOPS_API_MODE"] = "true"

            subprocess.run(
                ["safeops", "cloud", "scan"],
                check=True,
                env=env
            )
        except Exception as e:
            print("SCAN ERROR:", e)

        return {
            "success": True,
            "message": f"Applied {applied} high-signal fixes and refreshed scan"
        }

    if not issue_id:

        raise HTTPException(status_code=400, detail="issue_id required")

    try:

        if issue_id.startswith("default:AWS_SECURITY_GROUP_PUBLIC_PORT"):

            success = fix_security_group_public_port(issue_id, role_arn=role_arn)

        elif issue_id.startswith("default:S3_PUBLIC_BUCKET"):

            success = fix_s3_public_acl(issue_id, role_arn=role_arn)

        elif issue_id.startswith("default:AWS_RDS_PUBLIC_INSTANCE"):

            success = fix_rds_public_instance(issue_id, role_arn=role_arn)

        elif issue_id.startswith("default:AWS_IAM_PUBLIC_ASSUME_ROLE"):

            success = fix_iam_public_assume_role(issue_id, role_arn=role_arn)

        else:

            raise HTTPException(status_code=400, detail="Unsupported issue type")

        if success:
            from app.models import Activity
            from app.database import SessionLocal
            db = SessionLocal()
            db.add(Activity(
                action="fix",
                details=issue_id
            ))
            db.commit()
            try:
                env = os.environ.copy()
                env["SAFEOPS_API_MODE"] = "true"

                subprocess.run(
                    ["safeops", "cloud", "scan"],
                    check=True,
                    env=env
                )
            except Exception as e:
                print("SCAN ERROR:", e)

            return {
                "success": True,
                "message": "Fix applied and scan triggered"
            }

        return {
            "success": False,
            "message": "Fix failed or no change was applied."
        }

    except Exception as e:
        print("FIX ERROR:", repr(e))
        raise HTTPException(status_code=500, detail=str(e))
    
@router.post("/api/scan/run")
def run_scan():
    try:
        import os
        import subprocess

        env = os.environ.copy()
        env["SAFEOPS_API_MODE"] = "true"

        subprocess.run(
            ["safeops", "cloud", "scan"],
            check=True,
            env=env
        )

        from app.models import Activity
        from app.database import SessionLocal
        db = SessionLocal()
        db.add(Activity(
            action="scan",
            details="manual scan triggered"
        ))
        db.commit()

        return {
            "success": True,
            "message": "Scan completed successfully"
        }

    except Exception as e:
        print("SCAN RUN ERROR:", repr(e))
        raise HTTPException(status_code=500, detail=str(e))
    
@router.get("/api/activity")
def get_activity():
    from app.database import SessionLocal
    from app.models import Activity

    db = SessionLocal()
    return db.query(Activity).order_by(Activity.created_at.desc()).limit(10).all()

@router.get("/api/scans/history")
def get_scan_history():
    from app.database import SessionLocal
    from app.models import Scan

    db = SessionLocal()

    scans = (
        db.query(Scan)
        .order_by(Scan.created_at.asc())
        .limit(20)
        .all()
    )

    return [
        {
            "id": s.id,
            "risk_score": s.risk_score,
            "risk_level": s.risk_level,
            "created_at": s.created_at,
        }
        for s in scans
    ]