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

        print("\nApplying fix:")
        print(f"- Security Group: {sg_id}")
        print(f"- Port: {port}")
        print("- Action: remove public IPv4 and IPv6 ingress")

        removed_any = False

        # Remove public IPv4 ingress if present
        try:
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
            removed_any = True
            print("- Removed IPv4 public ingress 0.0.0.0/0")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")

            if error_code == "InvalidPermission.NotFound":
                print("- No IPv4 public ingress rule found")
            else:
                print(f"- AWS error removing IPv4 rule: {e}")

        # Remove public IPv6 ingress if present
        try:
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": port,
                        "ToPort": port,
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                    }
                ],
            )
            removed_any = True
            print("- Removed IPv6 public ingress ::/0")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")

            if error_code == "InvalidPermission.NotFound":
                print("- No IPv6 public ingress rule found")
            else:
                print(f"- AWS error removing IPv6 rule: {e}")

        if not removed_any:
            print("No matching public ingress rule found. It may already be fixed.")
            return False

        print("\nFix applied successfully.")
        return True

    except Exception as e:
        print(f"\nError while applying fix: {e}")
        return False