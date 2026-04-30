import subprocess
import time

from safeops.engine.findings import create_finding

SENSITIVE_PORTS = {
    22,
    3306,
    5432,
    6379,
    27017,
    8080
}


LOCAL_BIND_ADDRESSES = {
    "127.0.0.1",
    "::1",
    "localhost"
}

WILDCARD_BIND_ADDRESSES = {
    "0.0.0.0",
    "::",
    "*"
}

INTERESTING_PORTS = {
    22: "SSH",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    8080: "Web admin interface"
}


def _normalize_ip(ip):
    ip = ip.strip()

    if ip.startswith("*"):
        return "0.0.0.0"

    return ip


def _classify_exposure(ip, port):
    if ip in LOCAL_BIND_ADDRESSES:
        return None

    if ip in WILDCARD_BIND_ADDRESSES:
        severity = "critical" if port in INTERESTING_PORTS else "high"
        exposure_note = "Service is bound to all interfaces"
        return severity, exposure_note

    severity = "high" if port in INTERESTING_PORTS else "medium"
    exposure_note = f"Service is bound to non-local interface {ip}"
    return severity, exposure_note


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
                "module": "exposure",
                "status": "error",
                "error": result.stderr.strip(),
                "duration": round(time.time() - start_time, 3),
                "findings": []
            }

        lines = result.stdout.splitlines()
        seen_bindings = set()  # stores (ip, port)

        for line in lines[1:]:
            parts = line.split()

            if len(parts) < 9:
                continue

            protocol_info = parts[8]

            if "->" in protocol_info:
                continue

            if ":" not in protocol_info:
                continue

            try:
                address, port = protocol_info.rsplit(":", 1)
                port = int(port)
                ip = _normalize_ip(address)

                seen_bindings.add((ip, port))
            except ValueError:
                continue

        for ip, port in seen_bindings:
            # Ignore noisy high ephemeral ports
            if port not in SENSITIVE_PORTS and port >= 1024:
                continue

            classification = _classify_exposure(ip, port)

            if not classification:
                continue

            severity, exposure_note = classification
            service_name = INTERESTING_PORTS.get(port, "Service")

            findings.append(create_finding(
                issue_id="EXTERNALLY_REACHABLE_BINDING",
                fingerprint=f"EXTERNALLY_REACHABLE_BINDING:{ip}:{port}",
                title=f"{service_name} may be externally reachable (port {port})",
                severity=severity,
                description=f"{exposure_note}. Bound to {ip} on port {port}.",
                fix="Bind the service to localhost or a trusted interface, and restrict access using firewall rules.",
                auto_fix_supported=False,
                module="exposure",
                requires_elevation=False
            ))

        return {
            "module": "exposure",
            "status": "success",
            "error": None,
            "duration": round(time.time() - start_time, 3),
            "findings": findings
        }

    except Exception as e:
        return {
            "module": "exposure",
            "status": "error",
            "error": str(e),
            "duration": round(time.time() - start_time, 3),
            "findings": []
        }