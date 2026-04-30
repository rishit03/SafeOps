import argparse
import socket
from safeops.orchestrator.scan_runner import run_scan
from safeops.config.config_loader import load_config, update_config_value
from collections import defaultdict
from safeops.engine.state_manager import load_state, save_state
from datetime import datetime
from safeops.engine.risk_engine import (
    assign_statuses,
    calculate_risk_score,
    classify_risk_score,
    compare_risk_scores
)
from safeops.alerts.slack import send_slack_alert
from safeops.fixes.fix_runner import run_fixes
from safeops.fixes.backup_restore import restore_backup

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

def handle_scan(args):
    print("\n=== SafeOps Scan ===\n")

    results = run_scan()
    state = load_state()
    previous_findings = state.get("current_findings", [])
    all_findings = collect_all_findings(results)

    current_findings_with_status, resolved_findings = assign_statuses(
        all_findings,
        previous_findings
    )

    grouped_findings = group_findings_by_severity(current_findings_with_status)
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
            message_lines.append(f"[{f['severity'].upper()}][{f['status'].upper()}] {f['title']}")
        
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
    else:
        print("No findings detected.")

    print("\nModules")
    print("-------")
    for result in results:
        print(f"{result['module']:<10} {result['status']:<8} {result['duration']}s")
        if result["status"] == "error":
            print(f"  Error: {result['error']}")

    print()

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
    else:
        findings = current_findings

    fix_success = run_fixes(findings)

    if fix_success:
        print("SafeOps: re-running scan to refresh state...\n")
        handle_scan(args)


def handle_status(args):
    state = load_state()

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
    print("SafeOps: starting agent...")


def handle_stop(args):
    print("SafeOps: stopping agent...")


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
    fix_parser.set_defaults(func=handle_fix)

    status_parser = subparsers.add_parser("status", help="Show current SafeOps status")
    status_parser.set_defaults(func=handle_status)

    start_parser = subparsers.add_parser("start", help="Start the SafeOps agent")
    start_parser.set_defaults(func=handle_start)

    stop_parser = subparsers.add_parser("stop", help="Stop the SafeOps agent")
    stop_parser.set_defaults(func=handle_stop)

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

    return parser