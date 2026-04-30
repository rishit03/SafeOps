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


LOCAL_BIND_ADDRESSES = {
    "127.0.0.1",
    "::1",
    "localhost"
}

SERVICE_MANAGED_PORTS = {3306, 5432, 6379, 27017}


def _classify_exposure(ip, base_severity):
    if ip in LOCAL_BIND_ADDRESSES:
        return "medium", "Bound to localhost"
    return "critical", f"Bound to {ip} (potentially exposed)"


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
        open_ports = set()  # stores (ip, port)

        for line in lines[1:]:
            parts = line.split()

            if len(parts) < 9:
                continue

            protocol_info = parts[8]

            if "->" in protocol_info:
                continue  # skip established connections

            if ":" in protocol_info:
                try:
                    address, port = protocol_info.rsplit(":", 1)
                    port = int(port)
                    ip = address.strip()

                    if ip.startswith("*"):
                        ip = "0.0.0.0"

                    open_ports.add((ip, port))
                except ValueError:
                    continue

        for ip, port in open_ports:
            if port not in RISKY_PORTS:
                continue

            # Avoid duplicate localhost-only findings for service-specific ports.
            if port in SERVICE_MANAGED_PORTS and ip in LOCAL_BIND_ADDRESSES:
                continue

            title, base_severity = RISKY_PORTS[port]
            if ip in LOCAL_BIND_ADDRESSES:
                severity = "medium"
                exposure_note = "Bound to localhost"
            else:
                # Do NOT escalate here — exposure module handles it
                severity = base_severity
                exposure_note = f"Bound to {ip}"

            findings.append(create_finding(
                issue_id=f"OPEN_PORT_{port}",
                fingerprint=f"OPEN_PORT:{ip}:{port}",
                title=f"{title} (port {port})",
                severity=severity,
                description=f"Service detected on port {port}. {exposure_note}. Review if exposure is intended.",
                fix=f"Restrict access to port {port} using firewall rules or bind to localhost.",
                auto_fix_supported=False,
                module="ports",
                requires_elevation=False
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