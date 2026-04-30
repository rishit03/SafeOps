import os

from safeops.fixes.backup_restore import create_backup, restore_backup


SSH_CONFIG_PATH = "/etc/ssh/sshd_config"


def _update_ssh_setting(file_path, setting_name, new_value):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"SSH config not found: {file_path}")

    with open(file_path, "r") as file:
        lines = file.readlines()

    updated_lines = []
    setting_found = False

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("#"):
            updated_lines.append(line)
            continue

        if stripped.startswith(setting_name):
            updated_lines.append(f"{setting_name} {new_value}\n")
            setting_found = True
        else:
            updated_lines.append(line)

    if not setting_found:
        updated_lines.append(f"\n{setting_name} {new_value}\n")

    with open(file_path, "w") as file:
        file.writelines(updated_lines)


def fix_ssh_root_login():
    backup_path = create_backup(SSH_CONFIG_PATH)

    try:
        _update_ssh_setting(SSH_CONFIG_PATH, "PermitRootLogin", "no")
        return {
            "success": True,
            "message": "PermitRootLogin set to no.",
            "backup_path": backup_path
        }
    except Exception as e:
        restore_backup(backup_path, SSH_CONFIG_PATH)
        return {
            "success": False,
            "message": f"Failed to fix SSH root login: {e}",
            "backup_path": backup_path
        }


def fix_ssh_password_auth():
    backup_path = create_backup(SSH_CONFIG_PATH)

    try:
        _update_ssh_setting(SSH_CONFIG_PATH, "PasswordAuthentication", "no")
        return {
            "success": True,
            "message": "PasswordAuthentication set to no.",
            "backup_path": backup_path
        }
    except Exception as e:
        restore_backup(backup_path, SSH_CONFIG_PATH)
        return {
            "success": False,
            "message": f"Failed to fix SSH password authentication: {e}",
            "backup_path": backup_path
        }