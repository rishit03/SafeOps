import boto3
import json
import urllib.parse

from safeops.engine.findings import create_finding


def _statement_allows_public_assume_role(statement):
    if statement.get("Effect") != "Allow":
        return False

    principal = statement.get("Principal")
    action = statement.get("Action")

    if isinstance(action, list):
        allows_assume = "sts:AssumeRole" in action
    else:
        allows_assume = action == "sts:AssumeRole"

    if not allows_assume:
        return False

    if principal == "*":
        return True

    if isinstance(principal, dict):
        aws_principal = principal.get("AWS")
        if aws_principal == "*":
            return True
        if isinstance(aws_principal, list) and "*" in aws_principal:
            return True

    return False

def _statement_has_condition(statement):
    condition = statement.get("Condition")
    return bool(condition)


def scan_publicly_assumable_roles(profile=None):
    findings = []

    try:
        from safeops.cloud.aws.session import get_boto3_session
        session = get_boto3_session(profile=profile)
        iam = session.client("iam")
        paginator = iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                assume_role_policy = role.get("AssumeRolePolicyDocument")

                if assume_role_policy is None:
                    encoded_doc = role.get("AssumeRolePolicyDocument")
                    if encoded_doc:
                        assume_role_policy = json.loads(
                            urllib.parse.unquote(encoded_doc)
                        )

                if not assume_role_policy:
                    continue

                statements = assume_role_policy.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for statement in statements:
                    if _statement_allows_public_assume_role(statement):
                        has_condition = _statement_has_condition(statement)

                        severity = "high" if has_condition else "critical"
                        confidence = "medium" if has_condition else "high"
                        priority = "Verify now" if has_condition else "Fix now"

                        condition_note = (
                            " The trust policy includes conditions, so verify whether they sufficiently restrict access."
                            if has_condition
                            else " No restrictive condition was found in the matching trust statement."
                        )

                        findings.append(create_finding(
                            issue_id="AWS_IAM_PUBLIC_ASSUME_ROLE",
                            fingerprint=f"AWS_IAM_PUBLIC_ASSUME_ROLE:{role_name}",
                            title=f"IAM role may be broadly assumable: {role_name}",
                            severity=severity,
                            description=(
                                f"IAM role {role_name} has a trust policy that allows broad role assumption."
                                f"{condition_note}"
                            ),
                            fix="""1. Go to AWS Console → IAM → Roles
                    2. Select the role
                    3. Review Trust relationships
                    4. Remove '*' or overly broad principals
                    5. Restrict access to specific AWS accounts, services, or tightly scoped conditions""",
                            auto_fix_supported=False,
                            module="aws_iam",
                            requires_elevation=False,
                            why_it_matters=(
                                "Broad IAM trust policies can allow unintended principals to assume roles, especially when paired "
                                "with weak or missing conditions."
                            ),
                            impact=(
                                "Potential privilege escalation or unauthorized AWS access if the role grants sensitive permissions."
                            ),
                            confidence=confidence,
                            time_to_fix="10–30 minutes",
                            remediation_priority=priority
                        ))
                        break

        return {
            "module": "aws_iam",
            "status": "success",
            "error": None,
            "findings": findings
        }

    except Exception as e:
        return {
            "module": "aws_iam",
            "status": "error",
            "error": str(e),
            "findings": []
        }