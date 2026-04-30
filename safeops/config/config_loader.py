import json
import os
from safeops.config.defaults import DEFAULT_CONFIG

SAFEOPS_HOME = os.path.join(os.path.expanduser("~"), ".safeops")
CONFIG_PATH = os.path.join(SAFEOPS_HOME, "config.json")

def ensure_safeops_home_exists():
    os.makedirs(SAFEOPS_HOME, exist_ok=True)

def ensure_config_exists():
    ensure_safeops_home_exists()

    if not os.path.exists(CONFIG_PATH) or os.path.getsize(CONFIG_PATH) == 0:
        save_config(DEFAULT_CONFIG)


def load_config():
    ensure_config_exists()

    try:
        with open(CONFIG_PATH, "r") as file:
            config = json.load(file)
    except (json.JSONDecodeError, OSError):
        config = DEFAULT_CONFIG.copy()
        save_config(config)

    merged_config = DEFAULT_CONFIG.copy()
    merged_config.update(config)
    return merged_config


def save_config(config_data):
    with open(CONFIG_PATH, "w") as file:
        json.dump(config_data, file, indent=4)

def update_config_value(key, value):
    config = load_config()

    if key not in DEFAULT_CONFIG:
        raise KeyError(f"Unknown config key: {key}")

    default_value = DEFAULT_CONFIG[key]

    if isinstance(default_value, bool):
        if value.lower() in ["true", "1", "yes", "on"]:
            parsed_value = True
        elif value.lower() in ["false", "0", "no", "off"]:
            parsed_value = False
        else:
            raise ValueError(f"Invalid boolean value for '{key}': {value}")

    elif isinstance(default_value, int):
        parsed_value = int(value)

    elif isinstance(default_value, list):
        parsed_value = [item.strip() for item in value.split(",") if item.strip()]

    else:
        parsed_value = value

    config[key] = parsed_value
    save_config(config)
    return config