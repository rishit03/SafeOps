import time


def run():
    start_time = time.time()

    return {
        "module": "exposure",
        "status": "success",
        "error": None,
        "duration": round(time.time() - start_time, 3),
        "findings": []
    }