from botocore.exceptions import ClientError
from safeops.cloud.aws.session import get_boto3_session


def fix_s3_public_acl(issue_id, profile=None, role_arn=None):
    try:
        parts = issue_id.split(":")

        # Expected:
        # default:S3_PUBLIC_BUCKET:bucket-name
        if len(parts) != 3:
            print("Error: Invalid S3 issue ID format.")
            return False

        profile_label, issue_type, bucket_name = parts

        if issue_type != "S3_PUBLIC_BUCKET":
            print("Error: Unsupported S3 issue type.")
            return False

        session = get_boto3_session(profile=profile, role_arn=role_arn)
        s3 = session.client("s3")

        print(f"\nApplying fix:")
        print(f"- Bucket: {bucket_name}")
        print(f"- Action: block public access + remove public ACL")

        # Step 1: Block public access
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        # Step 2: Remove public ACL
        s3.put_bucket_acl(
            Bucket=bucket_name,
            ACL="private"
        )

        print("\nFix applied successfully.")
        return True

    except ClientError as e:
        print(f"\nAWS error while applying fix: {e}")
        return False

    except Exception as e:
        print(f"\nError while applying fix: {e}")
        return False