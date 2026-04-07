"""
netbox_integration.py — Push discovered hosts into NetBox.

Creates prerequisites (site, manufacturer, device role, device type) on the
fly if they don't already exist, then creates/updates devices and their
primary IP addresses.
"""

import os
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

NETBOX_URL   = os.getenv("NETBOX_URL", "").rstrip("/")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN", "")
CONFIDENCE_THRESHOLD = int(os.getenv("CONFIDENCE_THRESHOLD", 75))

API = f"{NETBOX_URL}/api"
HEADERS = {
    "Authorization": f"Token {NETBOX_TOKEN}",
    "Content-Type":  "application/json",
    "Accept":        "application/json",
}
REQ = dict(headers=HEADERS, timeout=15, verify=False)

# ── Defaults for auto-created prerequisites ──────────────────────────────────
DEFAULT_SITE_NAME = "PSL Lab"
DEFAULT_SITE_SLUG = "psl-lab"
DEFAULT_ROLE_NAME = "Unknown"
DEFAULT_ROLE_SLUG = "unknown"
DEFAULT_MFR_NAME  = "Unknown"
DEFAULT_MFR_SLUG  = "unknown"


def slugify(text: str) -> str:
    """Turn a name into a NetBox-friendly slug."""
    s = text.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")[:50]


# ── Generic get-or-create ────────────────────────────────────────────────────

def _get_or_create(endpoint: str, search_params: dict, create_payload: dict) -> dict | None:
    """Return existing object or create a new one. Returns the JSON dict."""
    url = f"{API}{endpoint}"
    r = requests.get(url, params=search_params, **REQ)
    if r.status_code == 200:
        results = r.json().get("results", [])
        if results:
            return results[0]
    # create
    r = requests.post(url, json=create_payload, **REQ)
    if r.status_code == 201:
        return r.json()
    print(f"    ✘ Failed to create {endpoint}: {r.status_code} {r.text[:200]}")
    return None


# ── Prerequisite helpers ─────────────────────────────────────────────────────

def ensure_site() -> int | None:
    obj = _get_or_create(
        "/dcim/sites/",
        {"slug": DEFAULT_SITE_SLUG},
        {"name": DEFAULT_SITE_NAME, "slug": DEFAULT_SITE_SLUG, "status": "active"},
    )
    return obj["id"] if obj else None


def ensure_manufacturer(name: str) -> int | None:
    slug = slugify(name)
    obj = _get_or_create(
        "/dcim/manufacturers/",
        {"slug": slug},
        {"name": name, "slug": slug},
    )
    return obj["id"] if obj else None


def ensure_device_role(name: str = DEFAULT_ROLE_NAME) -> int | None:
    slug = slugify(name)
    obj = _get_or_create(
        "/dcim/device-roles/",
        {"slug": slug},
        {"name": name, "slug": slug, "color": "9e9e9e"},
    )
    return obj["id"] if obj else None


def ensure_device_type(manufacturer_id: int, model: str, vendor_name: str = "") -> int | None:
    # slug must be globally unique, so prefix with vendor to avoid collisions
    slug = slugify(f"{vendor_name} {model}" if vendor_name else model)
    # search by manufacturer AND slug so each vendor gets its own type
    obj = _get_or_create(
        "/dcim/device-types/",
        {"manufacturer_id": manufacturer_id, "slug": slug},
        {"manufacturer": manufacturer_id, "model": model, "slug": slug},
    )
    return obj["id"] if obj else None


# ── Role inference from scan data ────────────────────────────────────────────

def infer_role(host: dict) -> str:
    """Guess a device role from open ports/services."""
    open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
    services = {p.get("service", "") for p in open_ports}
    port_nums = {p.get("port") for p in open_ports}

    if "http" in services or "https" in services or 80 in port_nums or 443 in port_nums:
        if "snmp" in services or 161 in port_nums:
            return "Network Device"
        return "Server"
    if "snmp" in services or 161 in port_nums:
        return "Network Device"
    if "ssh" in services or 22 in port_nums:
        return "Server"
    if "domain" in services or 53 in port_nums:
        return "DNS Server"
    if "dhcp" in services or "dhcps" in services:
        return "DHCP Server"
    return DEFAULT_ROLE_NAME


# ── Device push ──────────────────────────────────────────────────────────────

def device_name(host: dict) -> str:
    """Pick a human-readable name for the device."""
    hostnames = host.get("hostnames", [])
    if hostnames:
        return hostnames[0]
    return f"host-{host['ip'].replace('.', '-')}"


def push_device(host: dict, site_id: int, role_id: int, dtype_id: int) -> dict | None:
    """Create or update a device in NetBox. Returns device dict or None."""
    name = device_name(host)

    # check if device already exists by name
    r = requests.get(f"{API}/dcim/devices/", params={"name": name}, **REQ)
    if r.status_code == 200 and r.json().get("results"):
        existing = r.json()["results"][0]
        print(f"    Device '{name}' already exists (id={existing['id']}), skipping")
        return existing

    payload = {
        "name":        name,
        "site":        site_id,
        "role":        role_id,
        "device_type": dtype_id,
        "status":      "active",
    }
    if host.get("mac"):
        payload["description"] = f"MAC: {host['mac']}"

    r = requests.post(f"{API}/dcim/devices/", json=payload, **REQ)
    if r.status_code == 201:
        print(f"    ✔ Created device '{name}' (id={r.json()['id']})")
        return r.json()
    print(f"    ✘ Failed to create device '{name}': {r.status_code} {r.text[:200]}")
    return None


def assign_ip(device: dict, ip: str) -> None:
    """Create an interface + IP address and set it as the device's primary IPv4."""
    device_id = device["id"]

    # ensure a default interface exists
    iface = _get_or_create(
        "/dcim/interfaces/",
        {"device_id": device_id, "name": "eth0"},
        {"device": device_id, "name": "eth0", "type": "1000base-t"},
    )
    if not iface:
        return

    # create IP (with /24 mask) and assign to interface
    addr = f"{ip}/24"
    r = requests.get(f"{API}/ipam/ip-addresses/", params={"address": addr}, **REQ)
    if r.status_code == 200 and r.json().get("results"):
        ip_obj = r.json()["results"][0]
    else:
        r = requests.post(f"{API}/ipam/ip-addresses/", json={
            "address":           addr,
            "status":            "active",
            "assigned_object_type": "dcim.interface",
            "assigned_object_id":   iface["id"],
        }, **REQ)
        if r.status_code == 201:
            ip_obj = r.json()
        else:
            print(f"    ✘ Failed to create IP {addr}: {r.status_code} {r.text[:200]}")
            return

    # set as primary IP on device
    requests.patch(f"{API}/dcim/devices/{device_id}/",
                   json={"primary_ip4": ip_obj["id"]}, **REQ)


# ── Main entry point ─────────────────────────────────────────────────────────

def push_hosts_to_netbox(hosts: list[dict]) -> dict:
    """
    Push a list of discovered hosts into NetBox.

    Each host dict should match the parser.py output format:
        { ip, status, hostnames, mac, vendor, os, ports }

    Optionally include a "confidence" key (int 0-100) from Bryce's scoring.
    Hosts below CONFIDENCE_THRESHOLD are skipped.

    Returns {"pushed": N, "skipped": N, "failed": N}.
    """
    stats = {"pushed": 0, "skipped": 0, "failed": 0}

    if not NETBOX_URL or not NETBOX_TOKEN:
        print("    ✘ NETBOX_URL or NETBOX_TOKEN not set — skipping push")
        return stats

    # filter by confidence if scores are present
    qualified = []
    for h in hosts:
        score = h.get("confidence")
        if score is not None and score < CONFIDENCE_THRESHOLD:
            print(f"    Skipping {h['ip']} (confidence {score} < {CONFIDENCE_THRESHOLD})")
            stats["skipped"] += 1
            continue
        qualified.append(h)

    if not qualified:
        print("    No hosts qualified for NetBox push")
        return stats

    # ensure shared prerequisites
    site_id = ensure_site()
    if not site_id:
        print("    ✘ Could not create site — aborting push")
        return stats

    for h in qualified:
        vendor = h.get("vendor") or DEFAULT_MFR_NAME
        os_name = (h.get("os") or {}).get("name") or "Generic Device"
        role_name = infer_role(h)

        mfr_id   = ensure_manufacturer(vendor)
        role_id  = ensure_device_role(role_name)
        dtype_id = ensure_device_type(mfr_id, os_name, vendor) if mfr_id else None

        if not all([mfr_id, role_id, dtype_id]):
            stats["failed"] += 1
            continue

        device = push_device(h, site_id, role_id, dtype_id)
        if device:
            assign_ip(device, h["ip"])
            stats["pushed"] += 1
        else:
            stats["failed"] += 1

    return stats