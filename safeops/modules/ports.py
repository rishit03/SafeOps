import subprocess
import time

from safeops.engine.findings import create_finding


RISKY_PORTS = {
    22: ("SSH service exposed", "medium"),
    3306: ("MySQL exposed", "high"),
    5432: ("PostgreSQL exposed", "high"),
    6379: ("Redis exposed", "critical"),
    27017: ("MongoDB exposed", "critical"),
    8080: ("Web admin interface exposed", "medium")
}


def run():
    start_time = time.time()
    findings = []

    try:
        result = subprocess.run(
            ["lsof", "-i", "-P", "-n"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return {
                "module": "ports",
                "status": "error",
                "error": result.stderr.strip(),
                "duration": round(time.time() - start_time, 3),
                "findings": []
            }

        lines = result.stdout.splitlines()

        open_ports = set()

        for line in lines[1:]:  # skip header
            parts = line.split()

            if len(parts) < 9:
                continue

            name = parts[0]
            protocol_info = parts[8]

            if ":" in protocol_info:
                try:
                    port = int(protocol_info.split(":")[-1])
                    open_ports.add(port)
                except ValueError:
                    continue

        for port in open_ports:
            if port in RISKY_PORTS:
                title, severity = RISKY_PORTS[port]

                findings.append(create_finding(
                    issue_id=f"OPEN_PORT_{port}",
                    fingerprint=f"OPEN_PORT:{port}",
                    title=f"{title} (port {port})",
                    severity=severity,
                    description=f"Service running on port {port} may be exposed.",
                    fix=f"Restrict access to port {port} using firewall rules or bind to localhost.",
                    auto_fix_supported=False,
                    module="ports"
                ))

        return {
            "module": "ports",
            "status": "success",
            "error": None,
            "duration": round(time.time() - start_time, 3),
            "findings": findings
        }

    except Exception as e:
        return {
            "module": "ports",
            "status": "error",
            "error": str(e),
            "duration": round(time.time() - start_time, 3),
            "findings": []
        }