#!/usr/bin/env python3
"""
netbox_cleanup.py — Delete all devices and related objects from NetBox.
Run this to reset NetBox to a clean state before re-running the pipeline.

Deletes in dependency order:
  IP addresses → interfaces → devices → device types →
  device roles → manufacturers → site
"""

import os
import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

NETBOX_URL   = os.getenv("NETBOX_URL", "").rstrip("/")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN", "")

API = f"{NETBOX_URL}/api"
HEADERS = {
    "Authorization": f"Token {NETBOX_TOKEN}",
    "Content-Type":  "application/json",
    "Accept":        "application/json",
}
REQ = dict(headers=HEADERS, timeout=15, verify=False)


def get_all(endpoint):
    """Fetch all objects from a paginated endpoint."""
    items = []
    url = f"{API}{endpoint}?limit=100"
    while url:
        r = requests.get(url, **REQ)
        if r.status_code != 200:
            break
        data = r.json()
        items.extend(data.get("results", []))
        url = data.get("next")
    return items


def delete_all(endpoint, label):
    """Delete every object at the given endpoint."""
    items = get_all(endpoint)
    if not items:
        print(f"  {label}: nothing to delete")
        return
    for item in items:
        r = requests.delete(f"{API}{endpoint}{item['id']}/", **REQ)
        name = item.get("name") or item.get("display") or item.get("address") or item["id"]
        if r.status_code == 204:
            print(f"  ✔ Deleted {label}: {name}")
        else:
            print(f"  ✘ Failed to delete {label} {name}: {r.status_code}")


if __name__ == "__main__":
    print("NetBox Cleanup — deleting all pipeline-created objects\n")

    confirm = input("Are you sure? This deletes ALL devices, IPs, roles, etc. (yes/no): ")
    if confirm.strip().lower() != "yes":
        print("Aborted.")
        raise SystemExit(0)

    print()
    delete_all("/ipam/ip-addresses/",  "IP Address")
    delete_all("/dcim/interfaces/",    "Interface")
    delete_all("/dcim/devices/",       "Device")
    delete_all("/dcim/device-types/",  "Device Type")
    delete_all("/dcim/device-roles/",  "Device Role")
    delete_all("/dcim/manufacturers/", "Manufacturer")
    delete_all("/dcim/sites/",         "Site")

    print("\nDone — NetBox is clean.")