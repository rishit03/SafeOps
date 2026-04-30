import json
import os

SAFEOPS_HOME = os.path.join(os.path.expanduser("~"), ".safeops")
STATE_PATH = os.path.join(SAFEOPS_HOME, "state.json")

def ensure_safeops_home_exists():
    os.makedirs(SAFEOPS_HOME, exist_ok=True)

DEFAULT_STATE = {
    "last_scan_time": None,
    "current_findings": [],
    "previous_findings": [],
    "resolved_findings": [],
    "module_results": []
}

def ensure_state_exists():
    ensure_safeops_home_exists()

    if not os.path.exists(STATE_PATH) or os.path.getsize(STATE_PATH) == 0:
        save_state(DEFAULT_STATE)
        

def load_state():
    ensure_state_exists()

    try:
        with open(STATE_PATH, "r") as file:
            state = json.load(file)
    except (json.JSONDecodeError, OSError):
        state = DEFAULT_STATE.copy()
        save_state(state)

    merged_state = DEFAULT_STATE.copy()
    merged_state.update(state)
    return merged_state


def save_state(state_data):
    with open(STATE_PATH, "w") as file:
        json.dump(state_data, file, indent=4)