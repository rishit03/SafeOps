import time

from safeops.config.config_loader import load_config
from safeops.utils.logger import log_info


def start_scheduler(cloud_mode=False, profile=None):

    config = load_config()

    interval = config.get("scan_interval_minutes", 60)

    mode_label = "cloud" if cloud_mode else "local"
    profile_label = f", profile: {profile}" if profile else ""
    print(f"SafeOps scheduler started (interval: {interval} minutes, mode: {mode_label}{profile_label})")

    print("Press Ctrl+C to stop.\n")

    try:

        if cloud_mode:

            from safeops.cli.commands import handle_cloud_scan

            handle_cloud_scan(type("Args", (), {"changes": True, "profile": profile})(), silent=True)

        else:

            from safeops.cli.commands import handle_scan

            handle_scan(None, silent=True)

        while True:

            time.sleep(interval * 60)

            log_info(f"Scheduled {mode_label} scan triggered")

            if cloud_mode:

                from safeops.cli.commands import handle_cloud_scan

                handle_cloud_scan(type("Args", (), {"changes": True, "profile": profile})(), silent=True)

            else:

                from safeops.cli.commands import handle_scan

                handle_scan(None, silent=True)

    except KeyboardInterrupt:

        log_info(f"Scheduler stopped by user, mode={mode_label}")

        print("\nSafeOps scheduler stopped.")