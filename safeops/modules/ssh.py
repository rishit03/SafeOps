import os
import time

from safeops.engine.findings import create_finding


SSH_CONFIG_PATH = "/etc/ssh/sshd_config"


def run():
    start_time = time.time()
    findings = []

    try:
        if not os.path.exists(SSH_CONFIG_PATH):
            return {
                "module": "ssh",
                "status": "error",
                "error": f"{SSH_CONFIG_PATH} not found",
                "duration": round(time.time() - start_time, 3),
                "findings": []
            }

        with open(SSH_CONFIG_PATH, "r") as file:
            lines = file.readlines()

        config = {}

        for line in lines:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            parts = line.split()

            if len(parts) >= 2:
                key = parts[0]
                value = parts[1]
                config[key] = value

        # Check 1: Root login
        if config.get("PermitRootLogin", "yes").lower() == "yes":
            findings.append(create_finding(
                issue_id="SSH_ROOT_LOGIN",
                fingerprint=f"SSH_ROOT_LOGIN:{SSH_CONFIG_PATH}",
                title="SSH root login enabled",
                severity="critical",
                description="Root login over SSH is allowed.",
                fix="Set PermitRootLogin no in sshd_config and restart SSH.",
                auto_fix_supported=True,
                module="ssh",
                requires_elevation=True,
                why_it_matters="If an attacker gains access, they get full control of the system immediately.",
                impact="High risk of complete system compromise."
            ))

        # Check 2: Password authentication
        if config.get("PasswordAuthentication", "yes").lower() == "yes":
            findings.append(create_finding(
                issue_id="SSH_PASSWORD_AUTH",
                fingerprint=f"SSH_PASSWORD_AUTH:{SSH_CONFIG_PATH}",
                title="SSH password authentication enabled",
                severity="high",
                description="SSH allows password-based authentication.",
                fix="Set PasswordAuthentication no and use SSH keys.",
                auto_fix_supported=True,
                module="ssh",
                requires_elevation=True,
                why_it_matters="Password-based SSH access is vulnerable to brute-force attacks.",
                impact="Increased risk of unauthorized access if weak credentials are used."
            ))

        return {
            "module": "ssh",
            "status": "success",
            "error": None,
            "duration": round(time.time() - start_time, 3),
            "findings": findings
        }

    except Exception as e:
        return {
            "module": "ssh",
            "status": "error",
            "error": str(e),
            "duration": round(time.time() - start_time, 3),
            "findings": []
        }