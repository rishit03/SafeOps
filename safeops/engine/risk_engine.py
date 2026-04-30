SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}


def index_findings_by_fingerprint(findings):
    return {
        finding["fingerprint"]: finding
        for finding in findings
    }


def assign_statuses(current_findings, previous_findings):
    current_map = index_findings_by_fingerprint(current_findings)
    previous_map = index_findings_by_fingerprint(previous_findings)

    updated_current_findings = []
    resolved_findings = []

    for fingerprint, current in current_map.items():
        current_copy = current.copy()

        if fingerprint not in previous_map:
            current_copy["status"] = "new"
        else:
            previous = previous_map[fingerprint]

            current_severity = SEVERITY_RANK.get(current.get("severity", "low"), 1)
            previous_severity = SEVERITY_RANK.get(previous.get("severity", "low"), 1)

            if current_severity > previous_severity:
                current_copy["status"] = "worsened"
            else:
                current_copy["status"] = "existing"

        updated_current_findings.append(current_copy)

    for fingerprint, previous in previous_map.items():
        if fingerprint not in current_map:
            resolved = previous.copy()
            resolved["status"] = "resolved"
            resolved_findings.append(resolved)

    return updated_current_findings, resolved_findings