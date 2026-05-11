import boto3
from botocore.exceptions import ClientError

from safeops.engine.findings import create_finding


SENSITIVE_NAME_KEYWORDS = [
    "backup",
    "dump",
    "export",
    "customer",
    "customers",
    "invoice",
    "invoices",
    "payment",
    "payments",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "password",
    "passwd",
    "token",
    "key",
    "private",
    "prod",
    "production",
    "database",
    "db",
]

SENSITIVE_EXTENSIONS = [
    ".env",
    ".sql",
    ".dump",
    ".bak",
    ".backup",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".csv",
    ".xlsx",
    ".json",
]


def looks_sensitive_object_key(key: str) -> bool:
    lowered = key.lower()

    if any(keyword in lowered for keyword in SENSITIVE_NAME_KEYWORDS):
        return True

    if any(lowered.endswith(ext) for ext in SENSITIVE_EXTENSIONS):
        return True

    return False


def scan_sensitive_s3_object_names(s3, bucket_name: str, max_objects: int = 250):
    sensitive_keys = []

    paginator = s3.get_paginator("list_objects_v2")

    scanned = 0

    for page in paginator.paginate(Bucket=bucket_name):
        for obj in page.get("Contents", []):
            key = obj.get("Key", "")
            print(f"Scanning objects in bucket: {bucket_name}")
            print(f"Object key found: {key}")
            print(f"Sensitive keys detected in {bucket_name}: {sensitive_keys}")
            scanned += 1

            if looks_sensitive_object_key(key):
                sensitive_keys.append(key)

            if scanned >= max_objects:
                return sensitive_keys

    return sensitive_keys


def scan_s3_public_buckets(profile=None, role_arn=None):
    findings = []
    skipped_buckets = []

    try:
        from safeops.cloud.aws.session import get_boto3_session
        session = get_boto3_session(profile=profile, role_arn=role_arn)
        s3 = session.client("s3")
        buckets = s3.list_buckets()["Buckets"]

        for bucket in buckets:
            bucket_name = bucket["Name"]
            bucket_has_public_acl = False

            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)

                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")

                    if "AllUsers" in uri:
                        bucket_has_public_acl = True

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

            # Metadata-only sensitive object name scan
            try:
                sensitive_keys = scan_sensitive_s3_object_names(s3, bucket_name)

                if sensitive_keys:
                    severity = "critical" if bucket_has_public_acl else "high"

                    findings.append(create_finding(
                        issue_id="S3_SENSITIVE_OBJECT_NAMES",
                        fingerprint=f"S3_SENSITIVE_OBJECT_NAMES:{bucket_name}",
                        title=f"S3 bucket contains potentially sensitive object names: {bucket_name}",
                        severity=severity,
                        description=(
                            "This bucket contains object names that suggest sensitive data such as backups, credentials, "
                            "exports, invoices, database dumps, keys, or production data. SafeOps only inspected object names "
                            "and did not download object contents."
                        ),
                        fix=f"""1. Open AWS Console → S3 → {bucket_name}
2. Review the flagged object names
3. Confirm whether sensitive data belongs in this bucket
4. Restrict bucket access and enable encryption if needed
5. Move secrets, keys, or backups to safer storage where appropriate""",
                        auto_fix_supported=False,
                        module="aws_s3",
                        requires_elevation=False,
                        why_it_matters=(
                            "Sensitive-looking object names can indicate exposed backups, credentials, exports, or customer data. "
                            "If the bucket is public or broadly accessible, this can lead to serious data exposure."
                        ),
                        impact=(
                            "Potential exposure of sensitive files, operational secrets, backups, or customer/business data."
                        ),
                        confidence="medium",
                        time_to_fix="5–20 minutes",
                        remediation_priority="Investigate now"
                    ))

                    findings[-1]["resource_type"] = "s3_bucket"
                    findings[-1]["bucket_name"] = bucket_name
                    findings[-1]["sensitive_object_count"] = len(sensitive_keys)
                    findings[-1]["sample_sensitive_object_keys"] = sensitive_keys[:10]

            except ClientError as e:
                skipped_buckets.append({
                    "bucket": bucket_name,
                    "error": f"Could not list objects for sensitive-name scan: {str(e)}"
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
            "message": f"{len(skipped_buckets)} S3 bucket(s) could not be fully checked due to permission or access errors.",
            "details": skipped_buckets
        })

    return {
        "module": "aws_s3",
        "status": "success",
        "error": None,
        "findings": findings,
        "warnings": warnings
    }