from botocore.exceptions import ClientError

from safeops.cloud.aws.session import get_boto3_session


def fix_rds_public_instance(issue_id, profile=None, role_arn=None):
    try:
        parts = issue_id.split(":")

        # Expected:
        # default:AWS_RDS_PUBLIC_INSTANCE:database-1
        if len(parts) != 3:
            print("Error: Invalid RDS issue ID format.")
            return False

        profile_label, issue_type, db_instance_id = parts

        if issue_type != "AWS_RDS_PUBLIC_INSTANCE":
            print("Error: Unsupported RDS issue type.")
            return False

        session = get_boto3_session(profile=profile, role_arn=role_arn)
        rds = session.client("rds")

        print("\nApplying fix:")
        print(f"- RDS Instance: {db_instance_id}")
        print("- Action: disable Publicly Accessible")

        rds.modify_db_instance(
            DBInstanceIdentifier=db_instance_id,
            PubliclyAccessible=False,
            ApplyImmediately=True
        )

        print("\nFix requested successfully.")
        print("Note: RDS changes may take several minutes to fully apply.")
        return True

    except ClientError as e:
        print(f"\nAWS error while applying fix: {e}")
        return False

    except Exception as e:
        print(f"\nError while applying fix: {e}")
        return False