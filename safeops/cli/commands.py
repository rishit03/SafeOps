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
    cloud_scan_parser.set_defaults(func=handle_cloud_scan)

    cloud_check_parser = cloud_subparsers.add_parser(
        "check",
        help="Show a one-line cloud posture summary"
    )
    cloud_check_parser.add_argument(
        "--profile",
        help="AWS profile name to reference in output context"
    )
    cloud_check_parser.set_defaults(func=handle_cloud_check)
    doctor_parser = subparsers.add_parser("doctor", help="Check SafeOps setup and readiness")
    doctor_parser.set_defaults(func=handle_doctor)

    return parser

def is_first_run(state):
    return not state.get("last_scan_time")

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

        s3_result = scan_s3_public_buckets(profile=profile)
        sg_result = scan_security_groups(profile=profile)
        rds_result = scan_public_rds_instances(profile=profile)
        iam_result = scan_publicly_assumable_roles(profile=profile)

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

        message = "\n".join(message_lines)
        send_slack_alert(webhook_url, message)

    if args.changes and not filtered_findings and not module_errors and not scanner_warnings and not state_warning:
        if not silent:
            print("\n=== SafeOps Cloud Scan ===\n")
            print("No new or worsened cloud risks detected.\n")
        return

    if not should_print:
        return

    print("\n=== SafeOps Cloud Scan ===\n")

    top_risk = get_top_risk(filtered_findings)
    other_findings_count = max(0, len(filtered_findings) - 1)
    has_any_findings = len(filtered_findings) > 0

    if top_risk:
        print("TOP RISK")
        print("--------")
        print(f"{top_risk['severity'].upper()}")
        print(f"- {top_risk['title']}")
        print(f"  Why        : {top_risk['why_it_matters']}")
        print(f"  Impact     : {top_risk['impact']}")
        print(f"  Confidence : {top_risk.get('confidence', 'high').capitalize()}")
        print(f"  Fix        : {top_risk['fix']}")
        print(f"  Time to fix: {top_risk.get('time_to_fix', 'unknown')}")
        print(f"  Priority   : {top_risk.get('remediation_priority', 'Plan this')}")
        print()

    if not args.changes and has_any_findings:
        if other_findings_count > 0:
            print(f"(Other findings: {other_findings_count})\n")
    elif not args.changes and not has_any_findings:
        if scanner_warnings or module_errors:
            print("
            
            MYE09A@MYE09A
            \n")
        else:
            print("No high-signal cloud risks detected (based on available checks).\n")

    if new_count or worsened_count or resolved_count:
        print("Changes")
        print("-------")
        print(f"New findings      : {new_count}")
        print(f"Worsened findings : {worsened_count}")
        print(f"Resolved findings : {resolved_count}")
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
        print(f"Total Findings : {len(filtered_findings)}")

        critical_count = sum(
            1 for f in filtered_findings
            if f["severity"] == "critical"
        )
        high_count = sum(
            1 for f in filtered_findings
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

    critical_count = sum(
        1 for f in current_cloud_findings
        if f["severity"] == "critical"
    )
    high_count = sum(
        1 for f in current_cloud_findings
        if f["severity"] == "high"
    )

    profile_context = f" [{args.profile}]" if args.profile else " [all profiles]"

    print(
        f"SAFEOPS CLOUD CHECK{profile_context}: {cloud_risk_label.upper()} | "
        f"score={cloud_risk_score} | "
        f"findings={len(current_cloud_findings)} | "
        f"critical={critical_count} | "
        f"high={high_count} | "
        f"trend={cloud_trend}"
    )

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