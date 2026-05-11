from apscheduler.schedulers.background import BackgroundScheduler
from app.scan_engine import run_scan_and_store
from app.database import SessionLocal
from app.models import WorkspaceSettings

scheduler = BackgroundScheduler()


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


def start_scheduler():
    db = SessionLocal()

    try:
        settings = db.query(WorkspaceSettings).first()
        interval = settings.scan_frequency_minutes if settings else 60

    finally:
        db.close()

    if scheduler.running:
        return

    scheduler.add_job(
        scheduled_scan,
        "interval",
        minutes=interval,
        id="safeops_scheduled_scan",
        replace_existing=True,
    )

    scheduler.start()