from apscheduler.schedulers.background import BackgroundScheduler
from app.scan_engine import run_scan_and_store
from app.database import SessionLocal
from app.models import WorkspaceSettings

scheduler = BackgroundScheduler()
JOB_ID = "safeops_scheduled_scan"


def scheduled_scan():
    db = SessionLocal()

    try:
        settings = db.query(WorkspaceSettings).first()

        if not settings:
            return

        print("Running scheduled scan...")
        run_scan_and_store()

    finally:
        db.close()


def reschedule_scan_job(interval_minutes: int):
    if interval_minutes < 1:
        interval_minutes = 60

    if not scheduler.running:
        scheduler.start()

    scheduler.add_job(
        scheduled_scan,
        "interval",
        minutes=interval_minutes,
        id=JOB_ID,
        replace_existing=True,
    )

    print(f"Scheduled scan interval set to {interval_minutes} minutes")


def start_scheduler():
    db = SessionLocal()

    try:
        settings = db.query(WorkspaceSettings).first()
        interval = settings.scan_frequency_minutes if settings else 60

    finally:
        db.close()

    reschedule_scan_job(interval)