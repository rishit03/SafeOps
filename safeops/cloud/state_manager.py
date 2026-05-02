import json
import os


SAFEOPS_HOME = os.path.join(os.path.expanduser("~"), ".safeops")

DEFAULT_CLOUD_STATE = {
    "last_scan_time": None,
    "current_findings": [],
    "previous_findings": [],
    "resolved_findings": [],
    "state_warning": None
}


def ensure_safeops_home_exists():
    os.makedirs(SAFEOPS_HOME, exist_ok=True)


def _normalize_profile_label(profile=None):
    return profile if profile else "default"


def get_cloud_state_path(profile=None):
    profile_label = _normalize_profile_label(profile)
    return os.path.join(SAFEOPS_HOME, f"cloud_state_{profile_label}.json")


def ensure_cloud_state_exists(profile=None):
    ensure_safeops_home_exists()
    state_path = get_cloud_state_path(profile)

    if not os.path.exists(state_path) or os.path.getsize(state_path) == 0:
        save_cloud_state(DEFAULT_CLOUD_STATE.copy(), profile=profile)


def load_cloud_state(profile=None):
    ensure_cloud_state_exists(profile)
    state_path = get_cloud_state_path(profile)

    try:
        with open(state_path, "r") as file:
            state = json.load(file)
    except (json.JSONDecodeError, OSError):
        state = DEFAULT_CLOUD_STATE.copy()
        state["state_warning"] = (
            "Previous cloud scan state was reset because the state file was missing, corrupt, or unreadable. "
            "Change tracking may be inaccurate until the next clean scan."
        )
        save_cloud_state(state, profile=profile)

    merged_state = DEFAULT_CLOUD_STATE.copy()
    merged_state.update(state)
    return merged_state


def save_cloud_state(state_data, profile=None):
    ensure_safeops_home_exists()
    state_path = get_cloud_state_path(profile)

    state_to_save = DEFAULT_CLOUD_STATE.copy()
    state_to_save.update(state_data)

    with open(state_path, "w") as file:
        json.dump(state_to_save, file, indent=4)