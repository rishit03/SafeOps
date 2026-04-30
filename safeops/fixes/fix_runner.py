from safeops.fixes.ssh_fixes import fix_ssh_root_login, fix_ssh_password_auth
from safeops.utils.logger import log_info, log_warning, log_error
import os


FIX_FUNCTIONS = {
    "SSH_ROOT_LOGIN": fix_ssh_root_login,
    "SSH_PASSWORD_AUTH": fix_ssh_password_auth,
}


def is_running_as_root():
    return os.geteuid() == 0


def get_fixable_findings(findings):
    return [finding for finding in findings if finding.get("auto_fix_supported")]


def run_fixes(findings, apply=False):
    fixable_findings = get_fixable_findings(findings)

    if not fixable_findings:
        print("No fixable issues found.")
        log_info("No fixable findings available")
        return False

    if not apply:
        print("SafeOps Fix Plan (Dry Run)\n")
        print("No changes will be made. Re-run with '--apply' to execute fixes.\n")
    else:
        print("SafeOps Fix Plan\n")

    requires_elevation = any(
        finding.get("requires_elevation", False)
        for finding in fixable_findings
    )

    if apply and requires_elevation and not is_running_as_root():
        print("Warning: One or more selected fixes require elevated privileges (sudo).")
        print("Run SafeOps with sudo to apply system-level fixes.\n")

    successful_fix_applied = False

    for finding in fixable_findings:
        print(f"Issue: {finding['title']}")
        print(f"Severity: {finding['severity']}")
        print(f"Fix: {finding['fix']}")
        print()

    for finding in fixable_findings:
        confirm = input(f"Apply fix for '{finding['title']}'? (y/n): ").strip().lower()

        if confirm != "y":
            print(f"Skipped: {finding['title']}\n")
            continue

        if not apply:
            print(f"Dry run only: would apply fix for '{finding['title']}'\n")
            log_info(f"Dry run fix previewed: {finding['id']}")
            continue

        fix_func = FIX_FUNCTIONS.get(finding["id"])

        if not fix_func:
            print(f"No real fix function available for: {finding['id']}\n")
            continue

        if finding.get("requires_elevation", False) and not is_running_as_root():
            print(f"Skipping: {finding['title']}")
            print("Reason: This fix requires elevated privileges (sudo).\n")
            log_warning(f"Skipped fix due to missing privileges: {finding['id']}")
            continue

        print(f"Applying fix for: {finding['title']}")

        try:
            result = fix_func()
        except Exception as e:
            print(f"Failure: {str(e)}")
            print("Fix execution failed.\n")
            log_error(f"Fix execution exception for {finding['id']}: {str(e)}")
            continue

        if result["success"]:
            print(f"Success: {result['message']}")
            print(f"Backup created at: {result['backup_path']}")
            print("State will be refreshed automatically.\n")
            log_info(f"Fix succeeded: {finding['id']}")
            successful_fix_applied = True
        else:
            print(f"Failure: {result['message']}")
            print(f"Rollback attempted using backup: {result['backup_path']}\n")
            log_error(f"Fix failed: {finding['id']} - {result['message']}")

    return successful_fix_applied