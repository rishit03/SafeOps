import sys
import argparse
import socket
import time
from safeops.orchestrator.scan_runner import run_scan
from safeops.config.config_loader import load_config, update_config_value
from collections import defaultdict
from safeops.engine.state_manager import load_state, save_state
from datetime import datetime
from safeops.engine.risk_engine import (
    assign_statuses,
    calculate_risk_score,
    classify_risk_score,
    compare_risk_scores,
    get_top_risk
)
from safeops.alerts.slack import send_slack_alert
from safeops.fixes.fix_runner import run_fixes
from safeops.fixes.backup_restore import restore_backup
from safeops.utils.logger import log_info, log_warning, log_error
from safeops.agent.scheduler import start_scheduler
from safeops.cloud.aws.auth import validate_aws_setup
from safeops.cloud.aws.s3_scanner import scan_s3_public_buckets
from safeops.cloud.aws.security_groups import scan_security_groups
from safeops.cloud.aws.rds_scanner import scan_public_rds_instances
from safeops.cloud.aws.iam_scanner import scan_publicly_assumable_roles
from safeops.cloud.state_manager import load_cloud_state, save_cloud_state
from safeops.fixes.s3_fix import fix_s3_public_acl
from safeops.fixes.rds_fix import fix_rds_public_instance
from safeops.fixes.iam_fix import fix_iam_public_assume_role

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def collect_all_findings(results):
    findings = []
    for result in results:
        findings.extend(result.get("findings", []))
    return findings

def get_hostname():
    return socket.gethostname()

def group_findings_by_severity(findings):
    grouped = defaultdict(list)
    for finding in findings:
        severity = finding.get("severity", "low").lower()
        grouped[severity].append(finding)
    return grouped

def sort_for_fix_order(findings):
    priority_rank = {
        "Fix now": 3,
        "Fix soon": 2,
        "Verify now": 1,
        "Plan this": 0
    }

    severity_rank = {
        "critical": 3,
        "high": 2,
        "medium": 1,
        "low": 0
    }

    def key(f):
        pr = priority_rank.get(f.get("remediation_priority", ""), 0)
        sr = severity_rank.get(f.get("severity", ""), 0)
        return (pr, sr)

    return sorted(findings, key=key, reverse=True)

def handle_scan(args, silent=False):
    log_info("Scan started")

    state = load_state()
    first_run = is_first_run(state)
    
    results = run_scan()
    previous_findings = state.get("current_findings", [])
    all_findings = collect_all_findings(results)

    current_findings_with_status, resolved_findings = assign_statuses(
        all_findings,
        previous_findings
    )

    grouped_findings = group_findings_by_severity(current_findings_with_status)
    has_changes = any(
        f["status"] in ["new", "worsened"]
        for f in current_findings_with_status
    )

    risk_score = calculate_risk_score(current_findings_with_status)
    risk_label = classify_risk_score(risk_score)

    prev_score, curr_score, delta, trend = compare_risk_scores(
        previous_findings,
        current_findings_with_status
    )

    config = load_config()
    webhook_url = config.get("slack_webhook_url")

    alert_findings = [
        f for f in current_findings_with_status
        if f["status"] in ["new", "worsened"] and f["severity"] in ["critical", "high"]
    ]

    if alert_findings and webhook_url:
        critical_count = len([f for f in alert_findings if f["severity"] == "critical"])
        high_count = len([f for f in alert_findings if f["severity"] == "high"])

        message_lines = [
            "SafeOps Alert",
            "",
            f"Host: {get_hostname()}",
            f"Scan Time (UTC): {datetime.utcnow().isoformat()}",
            "",
            "Summary:",
            f"- Critical: {critical_count}",
            f"- High: {high_count}",
            "",
            "New or Worsening Risks:",
            ""
        ]

        for f in alert_findings:
            message_lines.append(
                f"[{f['severity'].upper()}][{f['status'].upper()}] {f['title']}"
            )

        message_lines.append("")
        message_lines.append("Suggested Actions:")
        message_lines.append("- Run: safeops status")
        message_lines.append("- Run: safeops fix")

        message = "\n".join(message_lines)
        send_slack_alert(webhook_url, message)

    updated_state = {
        "last_scan_time": datetime.utcnow().isoformat(),
        "current_findings": current_findings_with_status,
        "previous_findings": previous_findings,
        "resolved_findings": resolved_findings,
        "module_results": results
    }

    save_state(updated_state)

    if first_run:
        print("\n=== Welcome to SafeOps ===\n")
        print("Quick tips:")
        print("- Run 'safeops status' to view current posture")
        print("- Run 'safeops fix' to remediate issues")
        print("- Configure alerts with 'safeops config set slack_webhook_url <url>'")
        print("\nThis message will only be shown once.\n")

    from safeops.cloud.aws.auth import validate_aws_setup

    if not silent or has_changes:
        print("\n=== SafeOps Scan ===\n")

        print(f"Host: {get_hostname()}")
        print(f"Scan Time (UTC): {updated_state['last_scan_time']}\n")

        print("Summary")
        print("-------")
        for severity in SEVERITY_ORDER:
            count = len(grouped_findings.get(severity, []))
            print(f"{severity.capitalize():<8}: {count}")

        print()
        print(f"Risk Score : {risk_score}/100")
        print(f"Risk Level : {risk_label}")

        print()
        print(f"Previous Score : {prev_score}/100")
        print(f"Current Score  : {curr_score}/100")
        print(f"Change         : {delta:+} ({trend})")
        print()

        if current_findings_with_status:
            print("Findings")
            print("--------")
            for severity in SEVERITY_ORDER:
                findings = grouped_findings.get(severity, [])
                if not findings:
                    continue

                print(f"\n{severity.upper()}")
                for finding in findings:
                    print(f"- {finding['title']}")
                    print(f"  Status : {finding['status']}")
                    print(f"  Module : {finding['module']}")
                    print(f"  Fix    : {finding['fix']}")

                    if finding.get("why_it_matters"):
                        print(f"  Why    : {finding['why_it_matters']}")

                    if finding.get("impact"):
                        print(f"  Impact     : {finding['impact']}")
                        print(f"  Confidence : {finding.get('confidence', 'high').capitalize()}")

        else:
            print("No findings detected.")

        print("\nModules")
        print("-------")
        for result in results:
            print(f"{result['module']:<16} {result['status']:<8} {result['duration']}s")
            if result["status"] == "error":
                print(f"  Error: {result['error']}")

        print()
    else:
        print("No significant changes detected.")

    log_info(
        f"Scan completed: findings={len(current_findings_with_status)}, "
        f"risk_score={risk_score}, risk_level={risk_label}, "
        f"changes_detected={has_changes}"
    )

    aws_check = validate_aws_setup()

    if aws_check["success"]:
        print("SafeOps Cloud\n")
        print("AWS credentials detected.\n")
        print("Run:")
        print("  safeops cloud scan")
        print("\nto check for exposed AWS resources.\n")

def group_findings_by_status(findings):
    grouped = defaultdict(list)
    for finding in findings:
        status = finding.get("status", "unknown")
        grouped[status].append(finding)
    return grouped


def handle_fix(args):
    if getattr(args, "all_critical", False):
        print("\nSafeOps Fix All Critical")
        print("------------------------")

        from safeops.fixes.security_group_fix import fix_security_group_public_port
        from safeops.fixes.s3_fix import fix_s3_public_acl
        from safeops.fixes.rds_fix import fix_rds_public_instance
        from safeops.fixes.iam_fix import fix_iam_public_assume_role

        cloud_state = load_cloud_state(profile=getattr(args, "profile", None))
        current_findings = cloud_state.get("current_findings", [])

        critical_findings = [
            f for f in current_findings
            if f.get("severity") == "critical"
        ]

        if not critical_findings:
            print("No critical issues found.\n")
            return

        print(f"Found {len(critical_findings)} critical issue(s).\n")

        if not args.apply:
            print("Dry run mode. No changes were made.\n")
            print("Would apply:")

            for finding in critical_findings:
                issue_id = finding.get("fingerprint")
                title = finding.get("title", "Unknown issue")

                if issue_id.startswith("default:AWS_SECURITY_GROUP_PUBLIC_PORT"):
                    print(f"- Remove public security group ingress: {title}")

                elif issue_id.startswith("default:S3_PUBLIC_BUCKET"):
                    print(f"- Block public S3 bucket access: {title}")

                elif issue_id.startswith("default:AWS_RDS_PUBLIC_INSTANCE"):
                    print(f"- Disable public RDS accessibility: {title}")

                elif issue_id.startswith("default:AWS_IAM_PUBLIC_ASSUME_ROLE"):
                    print(f"- Restrict IAM trust policy: {title}")

                else:
                    print(f"- Unsupported fix: {title}")

            print("\nTo apply these fixes, run:")
            print("  safeops fix --all-critical --apply")
            return

        confirm = input("\nThis will apply multiple AWS fixes. Continue? [y/N]: ").strip().lower()

        if confirm != "y":
            print("Fix cancelled. No changes were made.")
            return

        applied = 0

        for finding in critical_findings:
            issue_id = finding.get("fingerprint")

            if issue_id.startswith("default:AWS_SECURITY_GROUP_PUBLIC_PORT"):
                success = fix_security_group_public_port(
                    issue_id,
                    profile=getattr(args, "profile", None),
                    role_arn=getattr(args, "role_arn", None)
                )

            elif issue_id.startswith("default:S3_PUBLIC_BUCKET"):
                success = fix_s3_public_acl(
                    issue_id,
                    profile=getattr(args, "profile", None),
                    role_arn=getattr(args, "role_arn", None)
                )

            elif issue_id.startswith("default:AWS_RDS_PUBLIC_INSTANCE"):
                success = fix_rds_public_instance(
                    issue_id,
                    profile=getattr(args, "profile", None),
                    role_arn=getattr(args, "role_arn", None)
                )

            elif issue_id.startswith("default:AWS_IAM_PUBLIC_ASSUME_ROLE"):
                success = fix_iam_public_assume_role(
                    issue_id,
                    profile=getattr(args, "profile", None),
                    role_arn=getattr(args, "role_arn", None)
                )

            else:
                success = False

            if success:
                applied += 1

        print(f"\nApplied {applied}/{len(critical_findings)} fixes successfully.")

        print("\nSafeOps: re-running cloud scan to refresh state...\n")

        class CloudScanArgs:
            changes = False
            profile = getattr(args, "profile", None)
            profiles = None

        handle_cloud_scan(CloudScanArgs())
        return

    if args.issue_id and args.issue_id.startswith("default:AWS_SECURITY_GROUP_PUBLIC_PORT"):
        from safeops.fixes.security_group_fix import fix_security_group_public_port

        print("\nSafeOps Fix")
        print("-----------")
        print(f"Issue: {args.issue_id}")

        if not args.apply:
            print("\nDry run mode. No changes were made.")
            print("To apply this fix, run:")
            print(f"  safeops fix {args.issue_id} --apply")
            return

        confirm = input("\nThis will modify AWS security group rules. Continue? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Fix cancelled. No changes were made.")
            return

        success = fix_security_group_public_port(
            args.issue_id,
            profile=getattr(args, "profile", None),
            role_arn=getattr(args, "role_arn", None)
        )
        if not success:
            print("\nFix failed. See error above.\n")
            return

        print("\nSafeOps: re-running cloud scan to refresh state...\n")

        class CloudScanArgs:
            changes = False
            profile = getattr(args, "profile", None)
            profiles = None

        handle_cloud_scan(CloudScanArgs())
        return

    elif args.issue_id and args.issue_id.startswith("default:S3_PUBLIC_BUCKET"):
        print("\nSafeOps Fix")
        print("-----------")
        print(f"Issue: {args.issue_id}")

        if not args.apply:
            print("\nDry run mode. No changes were made.")
            print("To apply this fix, run:")
            print(f"  safeops fix {args.issue_id} --apply")
            return

        confirm = input("\nThis will modify S3 bucket access. Continue? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Fix cancelled. No changes were made.")
            return

        success = fix_s3_public_acl(
            args.issue_id,
            profile=getattr(args, "profile", None),
            role_arn=getattr(args, "role_arn", None)
        )

        if not success:
            print("\nFix failed. See error above.\n")
            return

        print("\nSafeOps: re-running cloud scan to refresh state...\n")

        class CloudScanArgs:
            changes = False
            profile = getattr(args, "profile", None)
            profiles = None

        handle_cloud_scan(CloudScanArgs())
        return

    elif args.issue_id and args.issue_id.startswith("default:AWS_RDS_PUBLIC_INSTANCE"):
        print("\nSafeOps Fix")
        print("-----------")
        print(f"Issue: {args.issue_id}")

        if not args.apply:
            print("\nDry run mode. No changes were made.")
            print("To apply this fix, run:")
            print(f"  safeops fix {args.issue_id} --apply")
            return

        confirm = input("\nThis will modify RDS public accessibility. Continue? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Fix cancelled. No changes were made.")
            return

        success = fix_rds_public_instance(
            args.issue_id,
            profile=getattr(args, "profile", None),
            role_arn=getattr(args, "role_arn", None)
        )

        if not success:
            print("\nFix failed. See error above.\n")
            return

        print("\nSafeOps: re-running cloud scan to refresh state...\n")

        class CloudScanArgs:
            changes = False
            profile = getattr(args, "profile", None)
            profiles = None

        handle_cloud_scan(CloudScanArgs())
        return
    
    elif args.issue_id and args.issue_id.startswith("default:AWS_IAM_PUBLIC_ASSUME_ROLE"):
        print("\nSafeOps Fix")
        print("-----------")
        print(f"Issue: {args.issue_id}")

        if not args.apply:
            print("\nDry run mode. No changes were made.")
            print("To apply this fix, run:")
            print(f"  safeops fix {args.issue_id} --apply")
            return

        confirm = input("\nThis will modify IAM trust policy. Continue? [y/N]: ").strip().lower()

        if confirm != "y":
            print("Fix cancelled. No changes were made.")
            return

        success = fix_iam_public_assume_role(
            args.issue_id,
            profile=getattr(args, "profile", None),
            role_arn=getattr(args, "role_arn", None)
        )

        if not success:
            print("\nFix failed. See error above.\n")
            return

        print("\nSafeOps: re-running cloud scan to refresh state...\n")

        class CloudScanArgs:
            changes = False
            profile = getattr(args, "profile", None)
            profiles = None

        handle_cloud_scan(CloudScanArgs())
        return

    elif args.issue_id and args.issue_id.startswith("default:AWS_"):
        print("\nSafeOps Fix")
        print("-----------")
        print(f"Issue: {args.issue_id}")
        print("\nAutomatic fix is not supported for this cloud issue yet.")
        print("Use the manual fix steps from 'safeops cloud scan'.\n")
        return

    # Existing local fix path
    state = load_state()
    current_findings = state.get("current_findings", [])

    if args.issue_id:
        findings = [finding for finding in current_findings if finding["id"] == args.issue_id]
        if not findings:
            print(f"No matching issue found for ID: {args.issue_id}")
            return
        log_info(f"Fix command started for issue_id={args.issue_id}, apply={args.apply}")
    else:
        findings = current_findings
        log_info(f"Fix command started for all current findings, apply={args.apply}")

    fix_success = run_fixes(findings, apply=args.apply)

    if fix_success:
        log_info("At least one fix succeeded")
        print("SafeOps: re-running scan to refresh state...\n")
        handle_scan(args)
    else:
        log_warning("No fixes were applied successfully")


def handle_status(args):

    state = load_state()

    # --- compute everything first ---

    last_scan_time = state.get("last_scan_time")

    current_findings = state.get("current_findings", [])

    previous_findings = state.get("previous_findings", [])

    resolved_findings = state.get("resolved_findings", [])

    grouped_by_severity = group_findings_by_severity(current_findings)

    grouped_by_status = group_findings_by_status(current_findings)

    risk_score = calculate_risk_score(current_findings)

    risk_label = classify_risk_score(risk_score)

    prev_score, curr_score, delta, trend = compare_risk_scores(

        previous_findings,

        current_findings

    )

    # --- SUMMARY MODE FIRST ---

    if args.summary:

        print("\n=== SafeOps Summary ===\n")

        print(f"Host           : {get_hostname()}")

        print(f"Last Scan Time : {last_scan_time if last_scan_time else 'No scans yet'}")

        print(f"Risk Score     : {risk_score}/100")

        print(f"Risk Level     : {risk_label}")

        print(f"Change         : {delta:+} ({trend})")

        print(f"Findings       : {len(current_findings)}")

        print(

            f"Critical/High  : "

            f"{len(grouped_by_severity.get('critical', []))}/"

            f"{len(grouped_by_severity.get('high', []))}"

        )

        print()

        return   # <-- MUST EXIT HERE

    # --- FULL STATUS BELOW ---

    print("\n=== SafeOps Status ===\n")

    print(f"Host: {get_hostname()}")

    print(f"Last Scan Time (UTC): {last_scan_time if last_scan_time else 'No scans yet'}\n")

    print("Current Findings by Severity")

    print("----------------------------")

    for severity in SEVERITY_ORDER:

        count = len(grouped_by_severity.get(severity, []))

        print(f"{severity.capitalize():<8}: {count}")

    print("\nCurrent Findings by Status")

    print("--------------------------")

    for status in ["new", "existing", "worsened"]:

        count = len(grouped_by_status.get(status, []))

        print(f"{status.capitalize():<9}: {count}")

    print("\nOverall Risk")

    print("------------")

    print(f"Risk Score : {risk_score}/100")

    print(f"Risk Level : {risk_label}")

    print()

    print(f"Previous Score : {prev_score}/100")

    print(f"Current Score  : {curr_score}/100")

    print(f"Change         : {delta:+} ({trend})")

    if current_findings:
        print("\nCurrent Findings")
        print("----------------")
        for severity in SEVERITY_ORDER:
            findings = grouped_by_severity.get(severity, [])
            if not findings:
                continue

            print(f"\n{severity.upper()}")
            for finding in findings:
                print(f"- {finding['title']}")
                print(f"  Status : {finding['status']}")
                print(f"  Module : {finding['module']}")
                print(f"  Fix    : {finding['fix']}")

                if finding.get("why_it_matters"):
                    print(f"  Why    : {finding['why_it_matters']}")

                if finding.get("impact"):
                    print(f"  Impact     : {finding['impact']}")
                    print(f"  Confidence : {finding.get('confidence', 'high').capitalize()}")
                    
    else:
        print("\nNo current findings.")

    if resolved_findings:
        print("\nResolved Findings")
        print("-----------------")
        for finding in resolved_findings:
            print(f"- {finding['title']}")
            print(f"  Status : {finding['status']}")
            print(f"  Module : {finding['module']}")
    else:
        print("\nNo resolved findings.")

    print()


def handle_start(args):
    log_info(f"Start command invoked, cloud={args.cloud}, profile={getattr(args, 'profile', None)}")

    if args.cloud:
        auth = validate_aws_setup(profile=args.profile)
        if not auth["success"]:
            print(f"Error: {auth['error']}")
            return

    start_scheduler(cloud_mode=args.cloud, profile=getattr(args, "profile", None))


def handle_stop(args):
    print("SafeOps stop is not implemented yet. Use Ctrl+C to stop the scheduler.")


def handle_config(args):
    if args.action == "show":
        config = load_config()
        print("SafeOps Configuration:")
        for key, value in config.items():
            print(f"- {key}: {value}")

    elif args.action == "set":
        try:
            updated_config = update_config_value(args.key, args.value)
            print(f"SafeOps: updated '{args.key}' successfully.")
            print(f"New value: {updated_config[args.key]}")
        except KeyError as e:
            print(f"Config error: {e}")
        except ValueError as e:
            print(f"Config error: {e}")

    else:
        print("SafeOps: config command received.")

def handle_rollback(args):
    try:
        restore_backup(args.backup_path, args.original_path)
        print("SafeOps: rollback completed successfully.")
        print(f"Restored: {args.original_path}")
        print(f"From backup: {args.backup_path}")
        print("Next step: run 'python3 main.py scan' to refresh SafeOps state.")
    except Exception as e:
        print(f"SafeOps rollback failed: {e}")

def handle_check(args):
    state = load_state()

    current_findings = state.get("current_findings", [])
    previous_findings = state.get("previous_findings", [])

    grouped_by_severity = group_findings_by_severity(current_findings)

    risk_score = calculate_risk_score(current_findings)
    risk_label = classify_risk_score(risk_score)

    prev_score, curr_score, delta, trend = compare_risk_scores(
        previous_findings,
        current_findings
    )

    critical_count = len(grouped_by_severity.get("critical", []))
    high_count = len(grouped_by_severity.get("high", []))

    print(
        f"SAFEOPS CHECK: {risk_label.upper()} | "
        f"score={risk_score} | "
        f"findings={len(current_findings)} | "
        f"critical={critical_count} | "
        f"high={high_count} | "
        f"trend={trend}"
    )

    print()

    aws_check = validate_aws_setup()

    if aws_check["success"]:
        print("Hint: Run 'safeops cloud scan' to check AWS exposure.")

    log_info(
        f"Check command executed: risk_score={risk_score}, "
        f"risk_level={risk_label}, findings={len(current_findings)}, trend={trend}"
    )

    exit_code_map = {
        "Low": 0,
        "Moderate": 1,
        "High": 2,
        "Critical": 3,
    }

    sys.exit(exit_code_map.get(risk_label, 1))

def build_parser():
    parser = argparse.ArgumentParser(
        prog="safeops",
        description="SafeOps - Security posture and exposure scanner for startups"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a manual security scan")
    scan_parser.set_defaults(func=handle_scan)

    fix_parser = subparsers.add_parser("fix", help="Fix eligible issues")
    fix_parser.add_argument("issue_id", nargs="?", help="Optional issue ID to fix")
    fix_parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply real fixes instead of running in dry-run mode"
    )
    fix_parser.add_argument(
        "--profile",
        help="AWS profile name to use for cloud fixes"
    )
    fix_parser.add_argument(
        "--all-critical",
        action="store_true",
        help="Fix all supported critical cloud issues"
    )
    fix_parser.add_argument(
        "--role-arn",
        help="IAM Role ARN to assume for cloud fixes"
    )
    fix_parser.set_defaults(func=handle_fix)

    status_parser = subparsers.add_parser("status", help="Show current SafeOps status")
    status_parser.add_argument(
        "--summary",
        action="store_true",
        help="Show a compact summary view"
    )
    status_parser.set_defaults(func=handle_status)

    start_parser = subparsers.add_parser("start", help="Start the SafeOps scheduler")
    start_parser.add_argument(
        "--cloud",
        action="store_true",
        help="Run scheduled cloud scans instead of local scans"
    )
    start_parser.add_argument(
        "--profile",
        help="AWS profile name to use in cloud scheduler mode"
    )
    start_parser.set_defaults(func=handle_start)

    stop_parser = subparsers.add_parser("stop", help="Stop the SafeOps agent")
    stop_parser.set_defaults(func=handle_stop)

    check_parser = subparsers.add_parser("check", help="Show a one-line SafeOps health summary")
    check_parser.set_defaults(func=handle_check)

    config_parser = subparsers.add_parser("config", help="View or update configuration")
    config_subparsers = config_parser.add_subparsers(dest="action", required=True)

    config_show_parser = config_subparsers.add_parser("show", help="Show current config")
    config_show_parser.set_defaults(func=handle_config)

    config_set_parser = config_subparsers.add_parser("set", help="Set a config value")
    config_set_parser.add_argument("key", help="Config key to update")
    config_set_parser.add_argument("value", help="New value")
    config_set_parser.set_defaults(func=handle_config)

    rollback_parser = subparsers.add_parser("rollback", help="Restore a file from a SafeOps backup")
    rollback_parser.add_argument("backup_path", help="Path to the backup file")
    rollback_parser.add_argument("original_path", help="Path to the original file to restore")
    rollback_parser.set_defaults(func=handle_rollback)

    cloud_parser = subparsers.add_parser("cloud", help="Cloud security commands")
    cloud_subparsers = cloud_parser.add_subparsers(dest="cloud_command", required=True)

    cloud_scan_parser = cloud_subparsers.add_parser("scan", help="Scan cloud infrastructure")
    cloud_scan_parser.add_argument(
        "--changes",
        action="store_true",
        help="Show only new or worsened cloud findings"
    )
    cloud_scan_parser.add_argument(
        "--profile",
        help="AWS profile name to use"
    )
    cloud_scan_parser.add_argument(
        "--profiles",
        nargs="+",
        help="Multiple AWS profile names to scan"
    )
    cloud_scan_parser.add_argument(
        "--role-arn",
        help="IAM Role ARN to assume for cloud operations"
    )
    cloud_scan_parser.set_defaults(func=handle_cloud_scan)

    cloud_check_parser = cloud_subparsers.add_parser(
        "check",
        help="Show a one-line cloud posture summary"
    )
    cloud_check_parser.add_argument(
        "--profile",
        help="AWS profile name to reference in output context"
    )
    cloud_check_parser.add_argument(
        "--role-arn",
        help="IAM Role ARN to assume for cloud operations"
    )
    cloud_check_parser.set_defaults(func=handle_cloud_check)
    doctor_parser = subparsers.add_parser("doctor", help="Check SafeOps setup and readiness")
    doctor_parser.set_defaults(func=handle_doctor)

    return parser

def is_first_run(state):
    return not state.get("last_scan_time")

def estimate_fix_impact(top_risk, current_score):
    if not top_risk:
        return None

    severity = top_risk.get("severity", "low")

    reduction_map = {
        "critical": 40,
        "high": 20,
        "medium": 10,
        "low": 5
    }

    reduction = reduction_map.get(severity, 10)
    new_score = max(0, current_score - reduction)

    return {
        "reduction": reduction,
        "new_score": new_score
    }

def estimate_full_fix_impact(findings, current_score):
    if not findings:
        return None

    reduction_map = {
        "critical": 40,
        "high": 20,
        "medium": 10,
        "low": 5
    }

    total_reduction = 0
    total_time_min = 0
    total_time_max = 0

    for f in findings:
        severity = f.get("severity", "low")
        total_reduction += reduction_map.get(severity, 10)

        time_str = f.get("time_to_fix", "")
        if "-" in time_str:
            parts = time_str.replace("minutes", "").strip().split("-")
            try:
                total_time_min += int(parts[0].strip())
                total_time_max += int(parts[1].strip())
            except:
                pass

    total_reduction = min(total_reduction, current_score)

    new_score = max(0, current_score - total_reduction)

    return {
        "reduction": total_reduction,
        "new_score": new_score,
        "time_min": total_time_min,
        "time_max": total_time_max
    }

def handle_cloud_scan(args, silent=False):
    if args.profile and args.profiles:
        if not silent:
            print("Error: Use either --profile or --profiles, not both.")
        return

    if args.profiles:
        profiles_to_scan = args.profiles
    elif args.profile:
        profiles_to_scan = [args.profile]
    else:
        profiles_to_scan = [None]

    is_multi_profile = len(profiles_to_scan) > 1
    active_state_profile = profiles_to_scan[0] if len(profiles_to_scan) == 1 else None

    for profile in profiles_to_scan:
        auth = validate_aws_setup(profile=profile)
        if not auth["success"]:
            if not silent:
                print(f"Error: {auth['error']}")
            return

    if is_multi_profile and not silent:
        print(
            "Note: multi-profile scan output is shown live, but state tracking is only saved for single-profile scans.\n"
        )

    raw_results = []

    for profile in profiles_to_scan:
        profile_label = profile if profile else "default"

        role_arn = getattr(args, "role_arn", None)

        s3_result = scan_s3_public_buckets(profile=profile, role_arn=role_arn)
        sg_result = scan_security_groups(profile=profile, role_arn=role_arn)
        rds_result = scan_public_rds_instances(profile=profile, role_arn=role_arn)
        iam_result = scan_publicly_assumable_roles(profile=profile, role_arn=role_arn)

        raw_results.append({
            "profile": profile_label,
            "sections": {
                "AWS S3": {
                    "result": s3_result,
                    "clean_message": "No public S3 buckets detected."
                },
                "AWS Security Groups": {
                    "result": sg_result,
                    "clean_message": "No dangerous public security group rules detected."
                },
                "AWS RDS": {
                    "result": rds_result,
                    "clean_message": "No publicly accessible RDS instances detected."
                },
                "AWS IAM": {
                    "result": iam_result,
                    "clean_message": "No publicly assumable IAM roles detected."
                }
            }
        })

    all_findings = []
    module_errors = []
    scanner_warnings = []

    for profile_data in raw_results:
        profile_label = profile_data["profile"]

        for section_name, section_data in profile_data["sections"].items():
            result = section_data["result"]

            if result["status"] == "success":
                for finding in result.get("findings", []):
                    enriched_finding = finding.copy()
                    enriched_finding["profile"] = profile_label
                    enriched_finding["fingerprint"] = f"{profile_label}:{finding['fingerprint']}"
                    enriched_finding["title"] = f"[{profile_label}] {finding['title']}"
                    all_findings.append(enriched_finding)

                for warning in result.get("warnings", []):
                    scanner_warnings.append({
                        "profile": profile_label,
                        "section": section_name,
                        "type": warning.get("type", "warning"),
                        "message": warning.get("message", "Scanner reported a warning."),
                        "details": warning.get("details", [])
                    })
            else:
                module_errors.append({
                    "profile": profile_label,
                    "section": section_name,
                    "error": result.get("error", "Unknown error")
                })

    state_warning = None

    if is_multi_profile:
        previous_cloud_findings = []
    else:
        cloud_state = load_cloud_state(profile=active_state_profile)
        previous_cloud_findings = cloud_state.get("current_findings", [])
        state_warning = cloud_state.get("state_warning")

    current_cloud_findings_with_status, resolved_cloud_findings = assign_statuses(
        all_findings,
        previous_cloud_findings
    )

    new_count = sum(
        1 for f in current_cloud_findings_with_status
        if f["status"] == "new"
    )

    worsened_count = sum(
        1 for f in current_cloud_findings_with_status
        if f["status"] == "worsened"
    )

    resolved_count = len(resolved_cloud_findings)

    if args.changes:
        filtered_findings = [
            f for f in current_cloud_findings_with_status
            if f["status"] in ["new", "worsened"]
        ]
    else:
        filtered_findings = current_cloud_findings_with_status

    should_print = (
        not silent
        or bool(filtered_findings)
        or bool(module_errors)
        or bool(scanner_warnings)
        or bool(state_warning)
    )

    cloud_alert_findings = [
        f for f in current_cloud_findings_with_status
        if f["status"] in ["new", "worsened"] and f["severity"] in ["critical", "high"]
    ]

    cloud_risk_score = calculate_risk_score(current_cloud_findings_with_status)
    cloud_risk_label = classify_risk_score(cloud_risk_score)

    prev_cloud_score, curr_cloud_score, cloud_delta, cloud_trend = compare_risk_scores(
        previous_cloud_findings,
        current_cloud_findings_with_status
    )

    if not is_multi_profile:
        save_cloud_state({
            "last_scan_time": datetime.utcnow().isoformat(),
            "current_findings": current_cloud_findings_with_status,
            "previous_findings": previous_cloud_findings,
            "resolved_findings": resolved_cloud_findings
        }, profile=active_state_profile)

    import requests

    try:
        api_url = "http://127.0.0.1:8000/api/scans"

        payload = {
            "profile": profile_label if not is_multi_profile else "multi",
            "risk_score": cloud_risk_score,
            "risk_level": cloud_risk_label,
            "findings": [
                {
                    "fingerprint": f["fingerprint"],
                    "title": f["title"],
                    "severity": f["severity"],
                    "status": f["status"],
                    "module": f.get("module"),
                    "remediation_priority": f.get("remediation_priority"),
                    "raw": f
                }
                for f in current_cloud_findings_with_status
            ]
        }

        requests.post(api_url, json=payload, timeout=3)

    except Exception:
        pass

    config = load_config()
    webhook_url = config.get("slack_webhook_url")

    if cloud_alert_findings and webhook_url:
        alert_critical_count = sum(
            1 for f in cloud_alert_findings if f["severity"] == "critical"
        )
        alert_high_count = sum(
            1 for f in cloud_alert_findings if f["severity"] == "high"
        )

        message_lines = [
            "SafeOps Cloud Alert",
            "",
            f"Host: {get_hostname()}",
            f"Scan Time (UTC): {datetime.utcnow().isoformat()}",
            "",
            "Cloud Risk Summary:",
            f"- Critical: {alert_critical_count}",
            f"- High: {alert_high_count}",
            f"- Risk Score: {cloud_risk_score}/100",
            f"- Risk Level: {cloud_risk_label}",
            f"- Change: {cloud_delta:+} ({cloud_trend})",
            "",
            "New or Worsening Cloud Risks:",
            ""
        ]

        for finding in cloud_alert_findings:
            message_lines.append(
                f"[{finding['severity'].upper()}][{finding['status'].upper()}] {finding['title']}"
            )

        message_lines.append("")
        message_lines.append("Suggested Action:")
        message_lines.append("- Run: safeops cloud scan")
        message_lines.append("- Review exposed AWS resources immediately")

        message_lines.append("")
        message_lines.append("Run these to fix immediately:")

        for finding in cloud_alert_findings:
            issue_id = finding.get("fingerprint", "")
            title = finding.get("title", "Unknown issue")

            if issue_id.startswith("default:AWS_SECURITY_GROUP_PUBLIC_PORT"):
                message_lines.append(f"- {title}")
                message_lines.append(f"  safeops fix {issue_id} --apply")

            elif issue_id.startswith("default:S3_PUBLIC_BUCKET"):
                message_lines.append(f"- {title}")
                message_lines.append(f"  safeops fix {issue_id} --apply")

            elif issue_id.startswith("default:AWS_RDS_PUBLIC_INSTANCE"):
                message_lines.append(f"- {title}")
                message_lines.append(f"  safeops fix {issue_id} --apply")

            elif issue_id.startswith("default:AWS_IAM_PUBLIC_ASSUME_ROLE"):
                message_lines.append(f"- {title}")
                message_lines.append(f"  safeops fix {issue_id} --apply")

        message = "\n".join(message_lines)
        send_slack_alert(webhook_url, message)

    if args.changes and not filtered_findings and not module_errors and not scanner_warnings and not state_warning:
        if not silent:
            print("\nSAFEOPS CLOUD")
            print("-------------")
            print(f"Risk Level: {cloud_risk_label.capitalize()}")

            # safe: use current findings instead of display_findings
            top_risk = get_top_risk(filtered_findings)
            if top_risk:
                print(f"Top Risk: {top_risk['title']}")
            else:
                print("Top Risk: No new or worsened risks")

            print()
            print("=== SafeOps Cloud Scan ===\n")
            print("No new or worsened cloud risks detected.\n")
        return

    if not should_print:
        return

    rds_security_group_ids = set()

    for f in filtered_findings:
        if f.get("resource_type") == "rds_instance":
            for sg_id in f.get("security_group_ids", []):
                rds_security_group_ids.add(sg_id)

    display_findings = []

    for f in filtered_findings:
        is_related_rds_sg_finding = (
            f.get("resource_type") == "security_group"
            and f.get("port") in [3306, 5432]
            and f.get("security_group_id") in rds_security_group_ids
        )

        if not is_related_rds_sg_finding:
            display_findings.append(f)
            
    # Fix Groups (advanced grouping)
    fix_groups = []

    fix_all = estimate_full_fix_impact(display_findings, cloud_risk_score)

    print("\n=== SafeOps Cloud Scan ===\n")

    if fix_all and display_findings:
        print("Fix all high-signal issues")
        print("--------------------------")
        if fix_all["time_min"] > 0:
            print(f"- Estimated effort: ~{fix_all['time_min']}-{fix_all['time_max']} minutes")
        print(f"- Risk score improves by ~{fix_all['reduction']} points")
        print(f"- New estimated risk level: {classify_risk_score(fix_all['new_score']).capitalize()} ({fix_all['new_score']}/100)")
        print()
    
    if display_findings:
        ordered = sort_for_fix_order(display_findings)

        print("Fix order")
        print("---------")
        grouped_titles = set()

        for group in fix_groups:
            for item in group["items"]:
                grouped_titles.add(item["title"])

        filtered_order = [f for f in ordered if f["title"] not in grouped_titles]

        for i, f in enumerate(filtered_order, 1):
            priority = f.get("remediation_priority", "")
            print(f"{i}. {f['title']} ({priority})")
        print()

    top_risk = get_top_risk(display_findings)
    other_findings_count = max(0, len(display_findings) - 1)
    has_any_findings = len(display_findings) > 0

    if top_risk:
        print("TOP RISK")
        print("--------")
        print(f"{top_risk['severity'].upper()}")
        print(f"- {top_risk['title']}")
        print(f"  Issue ID   : {top_risk['fingerprint']}")
        print(f"  Why        : {top_risk['why_it_matters']}")
        print(f"  Impact     : {top_risk['impact']}")
        print(f"  Confidence : {top_risk.get('confidence', 'high').capitalize()}")
        fix_lines = top_risk['fix'].split("\n")
        print(f"  Fix        : {fix_lines[0]}")
        for line in fix_lines[1:]:
            print(f"  {' ' * 12}{line}")
        print(f"  Time to fix: {top_risk.get('time_to_fix', 'unknown')}")
        print(f"  Priority   : {top_risk.get('remediation_priority', 'Plan this')}")

        impact_estimate = estimate_fix_impact(top_risk, cloud_risk_score)
        if impact_estimate:
            print("  Impact if fixed:")
            print(f"  - Risk score improves by ~{impact_estimate['reduction']} points")
            print(f"  - Estimated new risk level: {classify_risk_score(impact_estimate['new_score']).capitalize()} ({impact_estimate['new_score']}/100)")

        print()

        rds_related = [
            f for f in display_findings
            if f.get("resource_type") in ["rds_instance", "security_group"]
            and (
                (f.get("resource_type") == "rds_instance")
                or (f.get("port") in [3306, 5432])
            )
        ]

        if rds_related:
            fix_groups.append({
                "title": "Public database exposure (RDS + network access)",
                "items": rds_related
            })

        if fix_groups:
            print("Fix Groups")
            print("----------")
            for group in fix_groups:
                print(f"{group['title']}:")
                for item in group["items"]:
                    print(f"- {item['title']}")
                print("Suggested action: Make database private and restrict security group access\n")

    if not args.changes and has_any_findings:
        if other_findings_count > 0:
            print(f"(Other findings: {other_findings_count} — run 'safeops cloud scan' for details)\n")

    elif not args.changes and not has_any_findings:
        if scanner_warnings or module_errors:
            print("No high-signal cloud risks detected (based on available checks).\n")
        else:
            print("No high-signal cloud risks detected. Your AWS setup looks good.\n")
            print("Run 'safeops start --cloud' to keep monitoring for new risks.\n")

    if new_count or worsened_count or resolved_count:
        print("Changes")
        print("-------")
        display_new_count = sum(
            1 for f in display_findings if f["status"] == "new"
        )
        print(f"New findings      : {display_new_count}")
        display_worsened_count = sum(
            1 for f in display_findings if f["status"] == "worsened"
        )
        print(f"Worsened findings : {display_worsened_count}")
        print(f"Resolved findings : {resolved_count}")
        print()

        if new_count > 0 or worsened_count > 0:
            print("Changed Issues")
            print("--------------")
            for f in display_findings:
                if f["status"] in ["new", "worsened"]:
                    priority = f.get("remediation_priority", "")
                    print(f"- [{f['severity'].upper()}][{f['status'].upper()}] {f['title']} ({priority})")
            print()

        if resolved_count > 0:
            print("Resolved Issues")
            print("----------------")
            for f in resolved_cloud_findings:
                print(f"- [{f['severity'].upper()}] {f['title']}")
            print()

    if module_errors or scanner_warnings or state_warning:
        print("Warnings")
        print("--------")

        if state_warning:
            print("State:")
            print(f"- {state_warning}")
            print()

        if module_errors:
            print("Some checks could not be completed. Results may be incomplete.")
            for err in module_errors:
                print(f"- [{err['profile']}] {err['section']}: {err['error']}")

        if scanner_warnings:
            print("Coverage:")
            for warning in scanner_warnings:
                print(f"- [{warning['profile']}] {warning['section']}: {warning['message']}")

        print()

    show_full_summary = (
        has_any_findings
        or new_count
        or worsened_count
        or resolved_count
        or bool(module_errors)
        or bool(scanner_warnings)
        or bool(state_warning)
    )

    if show_full_summary:
        print("Cloud Summary")
        print("-------------")
        print(f"Displayed Findings : {len(display_findings)}")
        print(f"Raw Detections     : {len(filtered_findings)}")

        critical_count = sum(
            1 for f in display_findings
            if f["severity"] == "critical"
        )
        high_count = sum(
            1 for f in display_findings
            if f["severity"] == "high"
        )

        print(f"Critical       : {critical_count}")
        print(f"High           : {high_count}")
        print(f"Risk Score     : {cloud_risk_score}/100")
        print(f"Risk Level     : {cloud_risk_label}")
        print(f"Previous Score : {prev_cloud_score}/100")
        print(f"Current Score  : {curr_cloud_score}/100")
        print(f"Change         : {cloud_delta:+} ({cloud_trend})")
        print()

        if not silent:
            print("SafeOps analyzed your AWS environment using high-signal checks.")
            print("Run 'safeops start --cloud' to monitor for new risks automatically.\n")

        if has_any_findings and not silent:
            print("Next:")
            print("- Fix the issue above")
            print("- Re-run: safeops cloud scan (confirm fix)")
            print("- Then run: safeops start --cloud (monitor continuously)")
            print("- Use: safeops cloud check (quick status anytime)")
            print()

def handle_cloud_check(args):
    auth = validate_aws_setup(profile=args.profile)
    if not auth["success"]:
        print(f"Error: {auth['error']}")
        return

    cloud_state = load_cloud_state(profile=args.profile)

    last_scan_time = cloud_state.get("last_scan_time")
    current_cloud_findings = cloud_state.get("current_findings", [])
    previous_cloud_findings = cloud_state.get("previous_findings", [])

    if args.profile:
        current_cloud_findings = [
            f for f in current_cloud_findings
            if f.get("profile") == args.profile
        ]
        previous_cloud_findings = [
            f for f in previous_cloud_findings
            if f.get("profile") == args.profile
        ]

    if not last_scan_time:
        print("\nSafeOps Cloud\n")
        print("No cloud scan data found.\n")
        print("Run:")
        if args.profile:
            print(f"  safeops cloud scan --profile {args.profile}")
        else:
            print("  safeops cloud scan")
        print("\nto analyze your AWS environment.\n")
        return

    if args.profile and not current_cloud_findings and not previous_cloud_findings:
        print("\nSafeOps Cloud\n")
        print(f"No cloud scan data found for profile '{args.profile}'.\n")
        print("Run:")
        print(f"  safeops cloud scan --profile {args.profile}")
        print("\nto analyze this AWS profile.\n")
        return

    cloud_risk_score = calculate_risk_score(current_cloud_findings)
    cloud_risk_label = classify_risk_score(cloud_risk_score)

    prev_cloud_score, curr_cloud_score, cloud_delta, cloud_trend = compare_risk_scores(
        previous_cloud_findings,
        current_cloud_findings
    )

    rds_security_group_ids = set()

    for f in current_cloud_findings:
        if f.get("resource_type") == "rds_instance":
            for sg_id in f.get("security_group_ids", []):
                rds_security_group_ids.add(sg_id)

    display_findings = []

    for f in current_cloud_findings:
        is_related_rds_sg_finding = (
            f.get("resource_type") == "security_group"
            and f.get("port") in [3306, 5432]
            and f.get("security_group_id") in rds_security_group_ids
        )

        if not is_related_rds_sg_finding:
            display_findings.append(f)

    critical_count = sum(
        1 for f in display_findings
        if f["severity"] == "critical"
    )
    high_count = sum(
        1 for f in display_findings
        if f["severity"] == "high"
    )

    top_risk = get_top_risk(display_findings)

    profile_context = f" [{args.profile}]" if args.profile else " [default]"

    print(
        f"SAFEOPS CLOUD CHECK{profile_context}: {cloud_risk_label.upper()} | "
        f"score={cloud_risk_score} | "
        f"findings={len(display_findings)} | "
        f"critical={critical_count} | "
        f"high={high_count} | "
        f"trend={cloud_trend}"
    )

    if top_risk:
        priority = top_risk.get("remediation_priority", "Review")
        print(f"Top Risk: [{top_risk['severity'].upper()}] {top_risk['title']} ({priority})")

    log_info(
        f"Cloud check executed: profile={args.profile}, "
        f"risk_score={cloud_risk_score}, "
        f"risk_level={cloud_risk_label}, "
        f"findings={len(current_cloud_findings)}, "
        f"trend={cloud_trend}"
    )

def handle_doctor(args):
    config = load_config()
    aws_check = validate_aws_setup()
    cloud_state = load_cloud_state()

    slack_webhook = config.get("slack_webhook_url")
    cloud_last_scan = cloud_state.get("last_scan_time")

    print("\nSafeOps Doctor")
    print("--------------")

    print("CLI install        : OK")
    print("Local config       : OK")
    print(f"Slack webhook      : {'Configured' if slack_webhook else 'Not configured'}")
    print(f"AWS credentials    : {'Detected' if aws_check['success'] else 'Not detected'}")
    print(f"Cloud state        : {'Initialized' if cloud_last_scan else 'Not initialized'}")

    print("\nRecommended next step:")

    if aws_check["success"] and not cloud_last_scan:
        print("  safeops cloud scan")
    elif not slack_webhook:
        print("  safeops config set slack_webhook_url <url>")
    else:
        print("  safeops check")
    print()