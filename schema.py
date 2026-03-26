from datetime import datetime
from zoneinfo import ZoneInfo

def make_scan_doc(*, cidr: str, live_count: int, discovery_args: list[str], deep_args: list[str], hosts: list[dict]) -> dict:
    ts = datetime.now(ZoneInfo("America/Denver")).isoformat()

    return {
        "scan_meta": {
            "cidr": cidr,
            "timestamp": ts,
            "live_count": live_count,
            "nmap_args": {
                "discovery": " ".join(discovery_args),
                "deep": " ".join(deep_args)
            }
        },
        "hosts": hosts
    }