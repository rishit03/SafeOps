from botocore.exceptions import ClientError

from safeops.cloud.aws.session import get_boto3_session


def fix_security_group_public_port(issue_id, profile=None, role_arn=None):
    try:
        parts = issue_id.split(":")

        # Expected format:
        # default:AWS_SECURITY_GROUP_PUBLIC_PORT:sg-xxxx:22
        if len(parts) != 4:
            print("Error: Invalid security group issue ID format.")
            return False

        profile_label, issue_type, sg_id, port_raw = parts

        if issue_type != "AWS_SECURITY_GROUP_PUBLIC_PORT":
            print("Error: Unsupported security group issue type.")
            return False

        port = int(port_raw)

        session = get_boto3_session(profile=profile, role_arn=role_arn)
        ec2 = session.client("ec2")

        print(f"\nApplying fix:")
        print(f"- Security Group: {sg_id}")
        print(f"- Port: {port}")
        print(f"- Action: remove 0.0.0.0/0 public ingress")

        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": port,
                    "ToPort": port,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        print("\nFix applied successfully.")
        return True

    except ClientError as e:
        print(f"\nAWS error while applying fix: {e}")
        return False

    except Exception as e:
        print(f"\nError while applying fix: {e}")
        return False