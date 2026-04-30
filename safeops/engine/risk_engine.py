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

SEVERITY_SCORE = {
    "critical": 40,
    "high": 20,
    "medium": 10,
    "low": 5
}


def calculate_risk_score(findings):
    total = 0

    for finding in findings:
        severity = finding.get("severity", "low")
        total += SEVERITY_SCORE.get(severity, 5)

    return min(total, 100)


def classify_risk_score(score):
    if score >= 70:
        return "Critical"
    if score >= 40:
        return "High"
    if score >= 20:
        return "Moderate"
    return "Low"


def compare_risk_scores(previous_findings, current_findings):
    prev_score = calculate_risk_score(previous_findings)
    curr_score = calculate_risk_score(current_findings)

    delta = curr_score - prev_score

    if delta > 0:
        trend = "Worsened"
    elif delta < 0:
        trend = "Improved"
    else:
        trend = "No Change"

    return prev_score, curr_score, delta, trend