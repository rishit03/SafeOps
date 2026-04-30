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
    requires_elevation=False
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
        "requires_elevation": requires_elevation
    }