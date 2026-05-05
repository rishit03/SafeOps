import boto3

from safeops.engine.findings import create_finding


RISKY_PORTS = {
    22: ("SSH exposed to the internet", "critical"),
    3306: ("MySQL exposed to the internet", "critical"),
    5432: ("PostgreSQL exposed to the internet", "critical"),
    6379: ("Redis exposed to the internet", "critical"),
    27017: ("MongoDB exposed to the internet", "critical"),
    8080: ("Web/admin service exposed to the internet", "high"),
}


def _is_public_cidr(ip_range):
    return ip_range in {"0.0.0.0/0", "::/0"}


def scan_security_groups(profile=None, role_arn=None):
    findings = []

    try:
        from safeops.cloud.aws.session import get_boto3_session
        session = get_boto3_session(profile=profile, role_arn=role_arn)
        ec2 = session.client("ec2")
        response = ec2.describe_security_groups()
        security_groups = response.get("SecurityGroups", [])

        for sg in security_groups:
            sg_id = sg.get("GroupId", "unknown")
            sg_name = sg.get("GroupName", "unknown")

            for permission in sg.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")

                if from_port is None or to_port is None:
                    continue

                for port, (title, severity) in RISKY_PORTS.items():
                    if from_port <= port <= to_port:
                        public_ipv4 = any(
                            _is_public_cidr(ip_range.get("CidrIp", ""))
                            for ip_range in permission.get("IpRanges", [])
                        )
                        public_ipv6 = any(
                            _is_public_cidr(ip_range.get("CidrIpv6", ""))
                            for ip_range in permission.get("Ipv6Ranges", [])
                        )

                        if public_ipv4 or public_ipv6:
                            finding = create_finding(
                                issue_id="AWS_SECURITY_GROUP_PUBLIC_PORT",
                                fingerprint=f"AWS_SECURITY_GROUP_PUBLIC_PORT:{sg_id}:{port}",
                                title=f"{title} in security group {sg_name} ({sg_id})",
                                severity=severity,
                                description=f"Security group {sg_name} ({sg_id}) allows inbound access from the public internet on port {port}.",
                                fix="""1. Go to AWS Console → EC2 → Security Groups
                            2. Select the affected security group
                            3. Edit inbound rules
                            4. Remove 0.0.0.0/0 access for this port
                            5. Restrict to your IP or internal network""",
                                auto_fix_supported=False,
                                module="aws_security_groups",
                                requires_elevation=False,
                                why_it_matters="Publicly exposed admin or database ports are common entry points for attackers.",
                                impact="High risk of unauthorized access, brute-force attacks, or direct service compromise.",
                                confidence="high",
                                time_to_fix="2–5 minutes",
                                remediation_priority="Fix now"
                            )

                            finding["resource_type"] = "security_group"
                            finding["security_group_id"] = sg_id
                            finding["security_group_name"] = sg_name
                            finding["port"] = port

                            findings.append(finding)

        return {
            "module": "aws_security_groups",
            "status": "success",
            "error": None,
            "findings": findings
        }

    except Exception as e:
        return {
            "module": "aws_security_groups",
            "status": "error",
            "error": str(e),
            "findings": []
        }