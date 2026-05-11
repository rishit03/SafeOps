from safeops.engine.findings import create_finding
from safeops.cloud.aws.session import get_boto3_session


PRIV_ESC_ACTIONS = {
    "iam:PassRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "sts:AssumeRole",
}


def extract_dangerous_actions(policy_doc):
    dangerous = set()

    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            action_lower = action.lower()

            if action == "*" or action_lower == "iam:*":
                dangerous.add(action)
                continue

            for risky_action in PRIV_ESC_ACTIONS:
                if action_lower == risky_action.lower():
                    dangerous.add(action)

    return dangerous


def scan_iam_privilege_escalation(profile=None, role_arn=None):
    findings = []

    try:
        session = get_boto3_session(profile=profile, role_arn=role_arn)
        iam = session.client("iam")

        paginator = iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                dangerous = set()

                # 1. Check attached managed policies
                attached_policies = iam.list_attached_role_policies(
                    RoleName=role_name
                ).get("AttachedPolicies", [])

                for policy in attached_policies:
                    policy_arn = policy["PolicyArn"]

                    policy_details = iam.get_policy(PolicyArn=policy_arn)
                    policy_version = policy_details["Policy"]["DefaultVersionId"]

                    policy_doc = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy_version,
                    )["PolicyVersion"]["Document"]

                    dangerous.update(extract_dangerous_actions(policy_doc))

                # 2. Check inline role policies
                inline_policy_names = iam.list_role_policies(
                    RoleName=role_name
                ).get("PolicyNames", [])

                for policy_name in inline_policy_names:
                    policy_doc = iam.get_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name,
                    )["PolicyDocument"]

                    dangerous.update(extract_dangerous_actions(policy_doc))

                if dangerous:
                    finding = create_finding(
                        issue_id="AWS_IAM_PRIV_ESC",
                        fingerprint=f"AWS_IAM_PRIV_ESC:{role_name}",
                        title=f"Privilege escalation risk in IAM role {role_name}",
                        severity="critical",
                        description="Role contains IAM permissions that may enable privilege escalation.",
                        fix="Restrict high-risk IAM actions and enforce least privilege.",
                        auto_fix_supported=False,  # ✅ ADD THIS LINE
                        module="aws_iam_priv_esc",
                        requires_elevation=False,
                        why_it_matters="Attackers can escalate privileges to gain full control over the AWS account.",
                        impact="Full account compromise possible.",
                        confidence="high",
                        time_to_fix="5–15 minutes",
                        remediation_priority="Fix now",
                    )

                    finding["resource_type"] = "iam_role"
                    finding["role_name"] = role_name
                    finding["dangerous_actions"] = sorted(dangerous)
                    finding["auto_fix_supported"] = False

                    findings.append(finding)

        return {
            "module": "aws_iam_priv_esc",
            "status": "success",
            "error": None,
            "findings": findings,
        }

    except Exception as e:
        return {
            "module": "aws_iam_priv_esc",
            "status": "error",
            "error": str(e),
            "findings": [],
        }