import os
import stat
import time

from safeops.engine.findings import create_finding


SENSITIVE_FILE_CANDIDATES = [
    ".env",
    ".env.local",
    "id_rsa",
    "id_ed25519",
    "config.json",
    "credentials.json"
]

SEARCH_PATHS = [
    os.getcwd(),
    os.path.expanduser("~/.ssh"),
]


def _is_world_readable(mode):
    return bool(mode & stat.S_IROTH)


def _is_world_writable(mode):
    return bool(mode & stat.S_IWOTH)


def _build_permission_finding(file_path, severity, issue_id, title_suffix, description, fix):
    return create_finding(
        issue_id=issue_id,
        fingerprint=f"{issue_id}:{file_path}",
        title=f"{title_suffix}: {file_path}",
        severity=severity,
        description=description,
        fix=fix,
        auto_fix_supported=False,
        module="file_permissions",
        requires_elevation=False,
        why_it_matters="Sensitive data can be accessed by unintended users.",
        impact="Potential leakage of credentials or secrets."
    )


def _check_file_permissions(file_path):
    findings = []

    try:
        file_stat = os.stat(file_path)
        mode = file_stat.st_mode

        if _is_world_writable(mode):
            findings.append(
                _build_permission_finding(
                    file_path=file_path,
                    severity="critical",
                    issue_id="FILE_WORLD_WRITABLE",
                    title_suffix="Sensitive file is world-writable",
                    description="A sensitive file is writable by all users on the system.",
                    fix="Restrict file permissions using chmod so only the owner can modify it."
                )
            )

        if _is_world_readable(mode):
            findings.append(
                _build_permission_finding(
                    file_path=file_path,
                    severity="high",
                    issue_id="FILE_WORLD_READABLE",
                    title_suffix="Sensitive file is world-readable",
                    description="A sensitive file is readable by all users on the system.",
                    fix="Restrict file permissions using chmod so only trusted users can read it."
                )
            )

    except Exception:
        # Skip unreadable or inaccessible files silently for now
        pass

    return findings


def run():
    start_time = time.time()
    findings = []

    try:
        for base_path in SEARCH_PATHS:
            if not os.path.exists(base_path):
                continue

            for root, dirs, files in os.walk(base_path):
                for filename in files:
                    if filename in SENSITIVE_FILE_CANDIDATES:
                        file_path = os.path.join(root, filename)
                        findings.extend(_check_file_permissions(file_path))

        return {
            "module": "file_permissions",
            "status": "success",
            "error": None,
            "duration": round(time.time() - start_time, 3),
            "findings": findings
        }

    except Exception as e:
        return {
            "module": "file_permissions",
            "status": "error",
            "error": str(e),
            "duration": round(time.time() - start_time, 3),
            "findings": []
        }