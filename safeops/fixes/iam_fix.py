from botocore.exceptions import ClientError
from safeops.cloud.aws.session import get_boto3_session
import json


def fix_iam_public_assume_role(issue_id, profile=None, role_arn=None):
    try:
        parts = issue_id.split(":")

        # Expected:
        # default:AWS_IAM_PUBLIC_ASSUME_ROLE:role-name
        if len(parts) != 3:
            print("Error: Invalid IAM issue ID format.")
            return False

        profile_label, issue_type, role_name = parts

        if issue_type != "AWS_IAM_PUBLIC_ASSUME_ROLE":
            print("Error: Unsupported IAM issue type.")
            return False

        session = get_boto3_session(profile=profile, role_arn=role_arn)
        iam = session.client("iam")

        print("\nApplying fix:")
        print(f"- IAM Role: {role_name}")
        print("- Action: restrict trust policy")

        role = iam.get_role(RoleName=role_name)
        policy = role["Role"]["AssumeRolePolicyDocument"]

        modified = False

        for statement in policy.get("Statement", []):
            principal = statement.get("Principal")

            if isinstance(principal, dict):
                aws_principal = principal.get("AWS")

                if aws_principal == "*" or (isinstance(aws_principal, list) and "*" in aws_principal):
                    # Replace with account-only access
                    account_id = session.client("sts").get_caller_identity()["Account"]

                    statement["Principal"]["AWS"] = f"arn:aws:iam::{account_id}:root"
                    modified = True

        if not modified:
            print("No unsafe principal found. Nothing to fix.")
            return False

        iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(policy)
        )

        print("\nFix applied successfully.")
        return True

    except ClientError as e:
        print(f"\nAWS error while applying fix: {e}")
        return False

    except Exception as e:
        print(f"\nError while applying fix: {e}")
        return False