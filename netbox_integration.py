"""
netbox_integration.py — Push discovered hosts into NetBox.

Creates prerequisites (site, manufacturer, device role, device type) on the
fly if they don't already exist, then creates/updates devices, their primary
IP addresses, MAC addresses, and their open-port services.
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
    slug = slugify(f"{vendor_name} {model}" if vendor_name else model)
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


# ── Description builder ──────────────────────────────────────────────────────

def build_description(host: dict) -> str:
    """Build a useful NetBox device description from scan data."""
    parts = []

    # OS name (from nmap)
    os_name = (host.get("os") or {}).get("name")
    if os_name:
        parts.append(os_name)

    # SNMP sysDescr (trimmed)
    snmp_desc = host.get("snmp_description")
    if snmp_desc:
        short = snmp_desc.split(",")[0][:80]
        parts.append(f"SNMP: {short}")

    # open port count + a few notable services
    open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
    if open_ports:
        notable = []
        for p in open_ports[:3]:
            svc = p.get("service") or str(p.get("port"))
            product = p.get("product")
            if product:
                notable.append(f"{svc} ({product})")
            else:
                notable.append(svc)
        more = "..." if len(open_ports) > 3 else ""
        parts.append(f"{len(open_ports)} open ports: {', '.join(notable)}{more}")

    return " | ".join(parts) if parts else ""


# ── Device push ──────────────────────────────────────────────────────────────

def device_name(host: dict) -> str:
    """Pick a human-readable name for the device."""
    if host.get("dns_hostname"):
        return host["dns_hostname"]
    hostnames = host.get("hostnames", [])
    if hostnames:
        return hostnames[0]
    return f"host-{host['ip'].replace('.', '-')}"


def push_device(host: dict, site_id: int, role_id: int, dtype_id: int) -> dict | None:
    """Create or update a device in NetBox. Returns device dict or None."""
    name = device_name(host)

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
    desc = build_description(host)
    if desc:
        payload["description"] = desc

    # surface the MAC as a custom field so it's visible on the device's main page
    if host.get("mac"):
        payload["custom_fields"] = {"primary_mac": host["mac"].upper()}

    r = requests.post(f"{API}/dcim/devices/", json=payload, **REQ)
    if r.status_code == 201:
        print(f"    ✔ Created device '{name}' (id={r.json()['id']})")
        return r.json()
    print(f"    ✘ Failed to create device '{name}': {r.status_code} {r.text[:200]}")
    return None


def assign_ip(device: dict, ip: str, mac: str | None = None) -> None:
    """Create an interface + IP address and set it as the device's primary IPv4.
    Optionally attach a MAC address to the interface."""
    device_id = device["id"]

    iface = _get_or_create(
        "/dcim/interfaces/",
        {"device_id": device_id, "name": "eth0"},
        {"device": device_id, "name": "eth0", "type": "1000base-t"},
    )
    if not iface:
        return

    # attach MAC to interface (NetBox 4.x uses a separate MACAddress object)
    if mac:
        mac_clean = mac.upper()
        r = requests.get(f"{API}/dcim/mac-addresses/", params={
            "mac_address": mac_clean,
            "interface_id": iface["id"],
        }, **REQ)
        if not (r.status_code == 200 and r.json().get("results")):
            r = requests.post(f"{API}/dcim/mac-addresses/", json={
                "mac_address":          mac_clean,
                "assigned_object_type": "dcim.interface",
                "assigned_object_id":   iface["id"],
            }, **REQ)
            if r.status_code == 201:
                mac_obj = r.json()
                # set as primary MAC on the interface
                requests.patch(f"{API}/dcim/interfaces/{iface['id']}/",
                               json={"primary_mac_address": mac_obj["id"]}, **REQ)
            else:
                print(f"    ✘ Failed to attach MAC {mac_clean}: {r.status_code} {r.text[:150]}")

    # create IP (with /24 mask) and assign to interface
    addr = f"{ip}/24"
    r = requests.get(f"{API}/ipam/ip-addresses/", params={"address": addr}, **REQ)
    if r.status_code == 200 and r.json().get("results"):
        ip_obj = r.json()["results"][0]
    else:
        r = requests.post(f"{API}/ipam/ip-addresses/", json={
            "address":              addr,
            "status":               "active",
            "assigned_object_type": "dcim.interface",
            "assigned_object_id":   iface["id"],
        }, **REQ)
        if r.status_code == 201:
            ip_obj = r.json()
        else:
            print(f"    ✘ Failed to create IP {addr}: {r.status_code} {r.text[:200]}")
            return

    requests.patch(f"{API}/dcim/devices/{device_id}/",
                   json={"primary_ip4": ip_obj["id"]}, **REQ)


# ── Services (open ports → NetBox Service objects) ───────────────────────────

def push_services(device_id: int, host: dict) -> int:
    """Create NetBox Service objects for each open port. Returns count created."""
    created = 0
    for p in host.get("ports", []):
        if p.get("state") != "open":
            continue

        port_num = p.get("port")
        proto = p.get("proto")
        service = p.get("service") or f"port-{port_num}"
        if not isinstance(port_num, int) or not proto:
            continue

        # skip if already exists on this device (NetBox 4.5 uses parent_object_*)
        r = requests.get(f"{API}/ipam/services/", params={
            "parent_object_id": device_id,
            "port": port_num,
            "protocol": proto,
        }, **REQ)
        if r.status_code == 200 and r.json().get("results"):
            continue

        desc_parts = []
        if p.get("product"):
            desc_parts.append(p["product"])
        if p.get("version"):
            desc_parts.append(p["version"])
        description = " ".join(desc_parts)[:200]

        payload = {
            "parent_object_type": "dcim.device",
            "parent_object_id":   device_id,
            "name":               service[:100],
            "ports":              [port_num],
            "protocol":           proto,
            "description":        description,
        }
        r = requests.post(f"{API}/ipam/services/", json=payload, **REQ)
        if r.status_code == 201:
            created += 1
        else:
            print(f"    ✘ Failed to create service {service}/{port_num}: {r.status_code} {r.text[:150]}")
    return created


# ── Main entry point ─────────────────────────────────────────────────────────

def push_hosts_to_netbox(hosts: list[dict]) -> dict:
    """
    Push a list of discovered hosts into NetBox.

    Each host dict should match the parser.py output format:
        { ip, status, hostnames, mac, vendor, os, ports }

    Optionally enriched in main.py with:
        dns_hostname, snmp_description, snmp_hostname

    Optionally include a "confidence" key (int 0-100) from scoring.
    Hosts below CONFIDENCE_THRESHOLD are skipped.

    Returns {"pushed": N, "skipped": N, "failed": N}.
    """
    stats = {"pushed": 0, "skipped": 0, "failed": 0}

    if not NETBOX_URL or not NETBOX_TOKEN:
        print("    ✘ NETBOX_URL or NETBOX_TOKEN not set — skipping push")
        return stats

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
            assign_ip(device, h["ip"], h.get("mac"))
            svc_count = push_services(device["id"], h)
            if svc_count:
                print(f"    → {svc_count} service(s) created for {device['name']}")
            stats["pushed"] += 1
        else:
            stats["failed"] += 1

    return stats