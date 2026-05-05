import boto3
from botocore.exceptions import ClientError

from safeops.engine.findings import create_finding


def scan_s3_public_buckets(profile=None, role_arn=None):
    findings = []

    # findings.append(create_finding(
    #     issue_id="TEST_PUBLIC_BUCKET",
    #     fingerprint="TEST_PUBLIC_BUCKET:demo",
    #     title="Test S3 bucket has public ACL access: demo-bucket",
    #     severity="critical",
    #     description="This is a test finding.",
    #     fix="No action needed (test).",
    #     auto_fix_supported=False,
    #     module="aws_s3",
    #     requires_elevation=False,
    #     why_it_matters="Testing change visibility.",
    #     impact="Test impact.",
    #     confidence="high",
    #     time_to_fix="1 minute",
    #     remediation_priority="Fix now"
    # ))
    skipped_buckets = []

    try:
        from safeops.cloud.aws.session import get_boto3_session
        session = get_boto3_session(profile=profile, role_arn=role_arn)
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
                            title=f"S3 bucket has public ACL access: {bucket_name}",
                            severity="high",
                            description=(
                                "This S3 bucket has an ACL grant that allows public access. "
                                "This may be intentional for static hosting or public assets, but should be verified."
                            ),
                            fix=f"""1. Open AWS Console → S3 → {bucket_name}
    2. Go to Permissions tab
    3. Enable 'Block all public access'
    4. Remove any public bucket policies or ACLs
    5. Verify the bucket is no longer publicly accessible""",
                            auto_fix_supported=False,
                            module="aws_s3",
                            requires_elevation=False,
                            why_it_matters=(
                                "Public S3 access can expose sensitive data if the bucket contains customer data, logs, backups, "
                                "internal exports, or application files."
                            ),
                            impact=(
                                "Potential data exposure. Risk is highest if this bucket stores non-public business, customer, "
                                "or application data."
                            ),
                            confidence="high",
                            time_to_fix="2–5 minutes",
                            remediation_priority="Verify now"
                        ))
                        break

            except ClientError as e:
                try:
                    pab = s3.get_public_access_block(Bucket=bucket_name)
                    config = pab.get("PublicAccessBlockConfiguration", {})

                    is_public_possible = not (
                        config.get("BlockPublicAcls", False)
                        and config.get("IgnorePublicAcls", False)
                        and config.get("BlockPublicPolicy", False)
                        and config.get("RestrictPublicBuckets", False)
                    )

                    if is_public_possible:
                        findings.append(create_finding(
                            issue_id="S3_POTENTIALLY_PUBLIC",
                            fingerprint=f"S3_POTENTIALLY_PUBLIC:{bucket_name}",
                            title=f"S3 bucket may allow public access: {bucket_name}",
                            severity="high",
                            description=(
                                "This S3 bucket could not be fully inspected due to permission or access limits. "
                                "Its public access settings suggest public exposure may be possible."
                            ),
                            fix=f"""1. Open AWS Console → S3 → {bucket_name}
    2. Go to Permissions tab
    3. Review 'Block all public access'
    4. Review bucket policies and ACLs
    5. Confirm whether public access is intentional""",
                            auto_fix_supported=False,
                            module="aws_s3",
                            requires_elevation=False,
                            why_it_matters=(
                                "Limited visibility can hide public exposure. This bucket should be verified because public access "
                                "settings may allow unintended access."
                            ),
                            impact=(
                                "Potential data exposure depending on bucket contents and effective public access configuration."
                            ),
                            confidence="medium",
                            time_to_fix="2–5 minutes",
                            remediation_priority="Verify now"
                        ))
                    else:
                        skipped_buckets.append({
                            "bucket": bucket_name,
                            "error": "Access restricted, but public access appears blocked"
                        })

                except ClientError:
                    skipped_buckets.append({
                        "bucket": bucket_name,
                        "error": str(e)
                    })

    except Exception as e:
        return {
            "module": "aws_s3",
            "status": "error",
            "error": str(e),
            "findings": [],
            "warnings": []
        }

    warnings = []
    if skipped_buckets:
        warnings.append({
            "type": "partial_scan",
            "message": f"{len(skipped_buckets)} S3 bucket(s) could not be checked due to permission or access errors.",
            "details": skipped_buckets
        })

    return {
        "module": "aws_s3",
        "status": "success",
        "error": None,
        "findings": findings,
        "warnings": warnings
    }