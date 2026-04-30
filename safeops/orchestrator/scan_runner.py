from safeops.config.config_loader import load_config

# Import modules
from safeops.modules import ssh, ports, exposure, firewall, services


MODULE_MAP = {
    "ssh": ssh,
    "ports": ports,
    "exposure": exposure,
    "firewall": firewall,
    "services": services
}


def run_scan():
    config = load_config()
    enabled_checks = config.get("enabled_checks", [])

    all_results = []

    for check in enabled_checks:
        module = MODULE_MAP.get(check)

        if not module:
            all_results.append({
                "module": check,
                "status": "error",
                "error": "Module not found",
                "duration": 0,
                "findings": []
            })
            continue

        try:
            result = module.run()
            all_results.append(result)
        except Exception as e:
            all_results.append({
                "module": check,
                "status": "error",
                "error": str(e),
                "duration": 0,
                "findings": []
            })

    return all_results