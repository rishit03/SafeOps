import subprocess
import time

from safeops.engine.findings import create_finding


RISKY_SERVICES = {
    6379: {
        "issue_id": "SERVICE_REDIS_RUNNING",
        "title": "Redis service detected",
        "severity": "high",
        "description": "Redis is running locally. If exposed or unauthenticated, it can present significant risk.",
        "fix": "Restrict Redis to localhost, require authentication, and limit network exposure."
    },
    27017: {
        "issue_id": "SERVICE_MONGODB_RUNNING",
        "title": "MongoDB service detected",
        "severity": "high",
        "description": "MongoDB is running locally. If exposed without proper access control, it can present significant risk.",
        "fix": "Bind MongoDB to localhost or trusted interfaces and enforce authentication."
    },
    3306: {
        "issue_id": "SERVICE_MYSQL_RUNNING",
        "title": "MySQL service detected",
        "severity": "medium",
        "description": "MySQL is running locally. Review network exposure and authentication settings.",
        "fix": "Restrict MySQL access to trusted hosts and verify strong authentication."
    },
    5432: {
        "issue_id": "SERVICE_POSTGRES_RUNNING",
        "title": "PostgreSQL service detected",
        "severity": "medium",
        "description": "PostgreSQL is running locally. Review bind settings and access controls.",
        "fix": "Restrict PostgreSQL access to trusted hosts and review pg_hba.conf rules."
    }
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
                "module": "services",
                "status": "error",
                "error": result.stderr.strip(),
                "duration": round(time.time() - start_time, 3),
                "findings": []
            }

        lines = result.stdout.splitlines()
        detected_ports = set()

        for line in lines[1:]:
            parts = line.split()

            if len(parts) < 9:
                continue

            protocol_info = parts[8]

            if ":" in protocol_info:
                try:
                    port = int(protocol_info.split(":")[-1])
                    detected_ports.add(port)
                except ValueError:
                    continue

        for port, service_info in RISKY_SERVICES.items():
            if port in detected_ports:
                findings.append(create_finding(
                    issue_id=service_info["issue_id"],
                    fingerprint=f"{service_info['issue_id']}:{port}",
                    title=f"{service_info['title']} (port {port})",
                    severity=service_info["severity"],
                    description=service_info["description"],
                    fix=service_info["fix"],
                    auto_fix_supported=False,
                    module="services",
                    requires_elevation=False
                ))

        return {
            "module": "services",
            "status": "success",
            "error": None,
            "duration": round(time.time() - start_time, 3),
            "findings": findings
        }

    except Exception as e:
        return {
            "module": "services",
            "status": "error",
            "error": str(e),
            "duration": round(time.time() - start_time, 3),
            "findings": []
        }