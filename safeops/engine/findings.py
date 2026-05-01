def create_finding(
    issue_id,
    fingerprint,
    title,
    severity,
    description,
    fix,
    auto_fix_supported,
    module,
    status=None,
    requires_elevation=False,
    why_it_matters=None,
    impact=None,
    confidence="high",
    time_to_fix=None,
    remediation_priority=None
):
    return {
        "id": issue_id,
        "fingerprint": fingerprint,
        "title": title,
        "severity": severity.lower(),
        "description": description,
        "fix": fix,
        "auto_fix_supported": auto_fix_supported,
        "module": module,
        "status": status,
        "requires_elevation": requires_elevation,
        "why_it_matters": why_it_matters,
        "impact": impact,
        "confidence": confidence,
        "time_to_fix": time_to_fix,
        "remediation_priority": remediation_priority
    }