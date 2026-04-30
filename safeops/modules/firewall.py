import subprocess
import time

from safeops.engine.findings import create_finding


def run():
    start_time = time.time()
    findings = []

    try:
        result = subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return {
                "module": "firewall",
                "status": "error",
                "error": result.stderr.strip(),
                "duration": round(time.time() - start_time, 3),
                "findings": []
            }

        output = result.stdout.lower()

        if "disabled" in output:
            findings.append(create_finding(
                issue_id="FIREWALL_DISABLED",
                fingerprint="FIREWALL_DISABLED:system",
                title="Firewall is disabled",
                severity="high",
                description="System firewall is not active, increasing exposure risk.",
                fix="Enable the system firewall to restrict unauthorized access.",
                auto_fix_supported=False,
                module="firewall"
            ))

        return {
            "module": "firewall",
            "status": "success",
            "error": None,
            "duration": round(time.time() - start_time, 3),
            "findings": findings
        }

    except Exception as e:
        return {
            "module": "firewall",
            "status": "error",
            "error": str(e),
            "duration": round(time.time() - start_time, 3),
            "findings": []
        }