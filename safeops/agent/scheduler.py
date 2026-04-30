import time

from safeops.config.config_loader import load_config
from safeops.utils.logger import log_info


def start_scheduler():
    config = load_config()
    interval = config.get("scan_interval_minutes", 60)

    log_info(f"Scheduler started with interval={interval} minutes")

    print(f"SafeOps scheduler started (interval: {interval} minutes)")
    print("Press Ctrl+C to stop.\n")

    try:
        # Run first scan immediately
        from safeops.cli.commands import handle_scan
        handle_scan(None, silent=True)

        while True:
            time.sleep(interval * 60)
            log_info("Scheduled scan triggered")
            from safeops.cli.commands import handle_scan
            handle_scan(None, silent=True)

    except KeyboardInterrupt:
        log_info("Scheduler stopped by user")
        print("\nSafeOps scheduler stopped.")