import boto3

from safeops.engine.findings import create_finding


def scan_public_rds_instances(profile=None, role_arn=None):
    findings = []

    try:
        from safeops.cloud.aws.session import get_boto3_session
        session = get_boto3_session(profile=profile, role_arn=role_arn)
        rds = session.client("rds")
        response = rds.describe_db_instances()
        db_instances = response.get("DBInstances", [])

        for db in db_instances:
            db_id = db.get("DBInstanceIdentifier", "unknown")
            engine = db.get("Engine", "unknown")
            publicly_accessible = db.get("PubliclyAccessible", False)
            security_group_ids = [
                sg.get("VpcSecurityGroupId")
                for sg in db.get("VpcSecurityGroups", [])
                if sg.get("VpcSecurityGroupId")
            ]

            if publicly_accessible:
                finding = create_finding(
                    issue_id="AWS_RDS_PUBLIC_INSTANCE",
                    fingerprint=f"AWS_RDS_PUBLIC_INSTANCE:{db_id}",
                    title=f"RDS instance is publicly accessible: {db_id}",
                    severity="critical",
                    description=f"RDS instance {db_id} ({engine}) is marked as publicly accessible.",
                    fix="""1. Go to AWS Console → RDS → Databases
                2. Select the instance
                3. Modify settings
                4. Disable 'Publicly Accessible'
                5. Ensure it is in a private subnet""",
                    auto_fix_supported=False,
                    module="aws_rds",
                    requires_elevation=False,
                    why_it_matters="Publicly accessible databases are common high-value targets for attackers.",
                    impact="High risk of unauthorized access, data exposure, and database compromise.",
                    confidence="high",
                    time_to_fix="5–10 minutes",
                    remediation_priority="Fix soon"
                )

                finding["resource_type"] = "rds_instance"
                finding["db_instance_id"] = db_id
                finding["engine"] = engine
                finding["security_group_ids"] = security_group_ids

                findings.append(finding)

        return {
            "module": "aws_rds",
            "status": "success",
            "error": None,
            "findings": findings
        }

    except Exception as e:
        return {
            "module": "aws_rds",
            "status": "error",
            "error": str(e),
            "findings": []
        }