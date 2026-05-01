import boto3
from botocore.exceptions import ClientError

from safeops.engine.findings import create_finding


def scan_s3_public_buckets(profile=None):
    findings = []

    try:
        from safeops.cloud.aws.session import get_boto3_session
        session = get_boto3_session(profile=profile)
        s3 = session.client("s3")
        buckets = s3.list_buckets()["Buckets"]

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)

                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")

                    if "AllUsers" in uri:
                        findings.append(create_finding(
                            issue_id="S3_PUBLIC_BUCKET",
                            fingerprint=f"S3_PUBLIC_BUCKET:{bucket_name}",
                            title=f"S3 bucket is publicly accessible: {bucket_name}",
                            severity="critical",
                            description="This S3 bucket allows public access.",
                            fix=f"""1. Open AWS Console → S3 → {bucket_name}
                            2. Go to Permissions tab
                            3. Enable 'Block all public access'
                            4. Remove any public bucket policies or ACLs
                            5. Verify the bucket is no longer publicly accessible""",
                            auto_fix_supported=False,
                            module="aws_s3",
                            requires_elevation=False,
                            why_it_matters="Public buckets can expose sensitive data to anyone on the internet.",
                            impact="High risk of data breach and data leakage.",
                            confidence="high",
                            time_to_fix="2–5 minutes",
                            remediation_priority="Fix now"
                        ))
                        break

            except ClientError:
                # Skip buckets we cannot access
                continue

    except Exception as e:
        return {
            "module": "aws_s3",
            "status": "error",
            "error": str(e),
            "findings": []
        }

    return {
        "module": "aws_s3",
        "status": "success",
        "error": None,
        "findings": findings
    }