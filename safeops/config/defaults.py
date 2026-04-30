DEFAULT_CONFIG = {
    "scan_interval_minutes": 60,
    "slack_webhook_url": "",
    "alert_min_severity": "high",
    "alert_on_status": ["new", "worsened"],
    "auto_fix_enabled": False,
    "require_confirmation_for_fix": True,
    "offline_mode": True,
    "log_level": "info",
    "enabled_checks": [
        "ssh",
        "ports",
        "exposure",
        "firewall",
        "services"
    ]
}