import os
import shutil
from datetime import datetime


def create_backup(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Cannot back up missing file: {file_path}")

    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    backup_path = f"{file_path}.bak.{timestamp}"

    shutil.copy2(file_path, backup_path)
    return backup_path


def restore_backup(backup_path, original_path):
    if not os.path.exists(backup_path):
        raise FileNotFoundError(f"Backup file not found: {backup_path}")

    shutil.copy2(backup_path, original_path)
    return original_path