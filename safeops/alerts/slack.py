import requests


def send_slack_alert(webhook_url, message):
    if not webhook_url:
        return

    payload = {
        "text": message
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=5)
        if response.status_code != 200:
            print(f"Slack alert failed: {response.text}")
    except Exception as e:
        print(f"Slack alert error: {e}")