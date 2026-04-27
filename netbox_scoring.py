"""
netbox_scoring.py — Apply confidence scores and pass/fail flags to NetBox devices.

Auto-creates custom fields and tags via the API if they don't already exist.
Call apply_scoring(device_id, score_data) after pushing a device.

Score data format (from Bryce's scoring module):
{
    "existence": {
        "snmp_response":    True/False,
        "nmap_open_ports":  True/False,
        "dhcp_active_lease": True/False,
        "dns_resolves":     True/False,
        "score": 0-100
    },
    "identity": {
        "multi_source":         True/False,
        "dhcp_present":         True/False,
        "mac_present":     True/False,
        "mac_conflict": True/False,
        "hostname_present":   True/False,
        "hostname_conflict": True/False,
        "manufacturer_present": True/False,
        "score": 0-100
    },
    "classification": {
        "snmp_sysobjectid":      True/False,
        "nmap_service_profile":  True/False,
        "ieee_oui_manufacturer": True/False,
        "dns_naming_convention": True/False,
        "score": 0-100
    },
    "total": 0-100
}
"""

from cProfile import label
import os
import requests
import urllib3
from datetime import datetime, timezone

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

# ── Colors ───────────────────────────────────────────────────────────────────
COLOR_PASS = "4caf50"   # green
COLOR_FAIL = "f44336"   # red

# ── Scoring checks mapped to tag names ───────────────────────────────────────
EXISTENCE_CHECKS = {
    "snmp_response":     "SNMP Response",
    "nmap_open_ports":   "Nmap Open Ports",
    "dhcp_active_lease": "DHCP Active Lease",
    "dns_resolves":      "DNS Resolves",
}

IDENTITY_CHECKS = {
    "multi_source":         "Seen by Multiple Sources",
    "dhcp_present":         "DHCP Lease Exists",
    "mac_present":     "MAC Address Observed",
    "mac_conflict": "MAC Conflict Detected",
    "hostname_present":   "Hostname Observed by Sources",
    "hostname_conflict": "Hostname Conflict Detected",
    "manufacturer_present": "Manufacturer/Vendor Evidence",
}

CLASSIFICATION_CHECKS = {
    "snmp_sysobjectid":      "SNMP sysObjectID",
    "nmap_service_profile":  "Nmap Service Profile",
    "ieee_oui_manufacturer": "IEEE OUI Manufacturer",
    "dns_naming_convention": "DNS Naming Convention",
}

# ── Custom fields to create on Device ────────────────────────────────────────
CUSTOM_FIELDS = [
    {"name": "confidence_existence",      "label": "Confidence: Existence",      "type": "integer"},
    {"name": "confidence_identity",       "label": "Confidence: Identity",       "type": "integer"},
    {"name": "confidence_classification", "label": "Confidence: Classification", "type": "integer"},
    {"name": "confidence_total",          "label": "Confidence: Total",          "type": "integer"},
    {"name": "last_seen",                 "label": "Last Seen",                  "type": "date"},
    {"name": "primary_mac",               "label": "Primary MAC",                "type": "text"},
]


# ── Slug helper ──────────────────────────────────────────────────────────────

def _slug(text):
    import re
    s = text.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")[:50]


# ── Setup: ensure custom fields and tags exist ───────────────────────────────

def _ensure_custom_field(name, label, field_type="integer"):
    """Create a custom field on dcim.device if it doesn't exist."""
    url = f"{API}/extras/custom-fields/"
    r = requests.get(url, params={"name": name}, **REQ)
    if r.status_code == 200 and r.json().get("results"):
        return r.json()["results"][0]

    payload = {
        "name":          name,
        "label":         label,
        "type":          field_type,
        "object_types":  ["dcim.device"],
        "required":      False,
        "ui_visible":    "always",
        "ui_editable":   "yes",
    }
    r = requests.post(url, json=payload, **REQ)
    if r.status_code == 201:
        print(f"    ✔ Created custom field: {label}")
        return r.json()
    print(f"    ✘ Failed to create custom field '{name}': {r.status_code} {r.text[:200]}")
    return None


def _ensure_tag(label, passed, weight=None):
    """Create a pass or fail tag if it doesn't exist. Returns tag dict."""
    suffix = "pass" if passed else "fail"
    color = COLOR_PASS if passed else COLOR_FAIL

    weight_str = f" ({weight:+})" if weight is not None else ""
    tag_name = f"{label}{weight_str} — {'Pass' if passed else 'Fail'}"
    slug = _slug(f"{label}-{weight}-{suffix}")

    url = f"{API}/extras/tags/"
    r = requests.get(url, params={"slug": slug}, **REQ)
    if r.status_code == 200 and r.json().get("results"):
        return r.json()["results"][0]

    payload = {"name": tag_name, "slug": slug, "color": color}
    r = requests.post(url, json=payload, **REQ)
    if r.status_code == 201:
        return r.json()

    print(f"    ✘ Failed to create tag '{tag_name}': {r.status_code} {r.text[:200]}")
    return None


def ensure_scoring_fields():
    """Pre-create all custom fields. Call once at pipeline start."""
    print("    Ensuring scoring custom fields exist...")
    for cf in CUSTOM_FIELDS:
        _ensure_custom_field(cf["name"], cf["label"], cf["type"])


# ── Apply scoring to a device ────────────────────────────────────────────────

def apply_scoring(device_id, score_data):
    """
    Apply confidence scores and pass/fail tags to an existing NetBox device.

    device_id:  NetBox device ID (int)
    score_data: dict matching the format described at the top of this file
    """
    if not score_data:
        return

    # ── Collect tags ─────────────────────────────────────────────────────
    tag_ids = []

    def _process_checks(checks_map, category_data):
        for key, label in checks_map.items():
            if key in category_data and key != "score":
                passed = bool(category_data[key])
                # mac_mismatch_penalty is inverted: True = bad
                if key in ("mac_conflict", "hostname_conflict"):
                    passed = not passed
                weight = category_data.get(f"{key}_weight")
                tag = _ensure_tag(label, passed, weight)
                if tag:
                    tag_ids.append({"id": tag["id"]})

    existence = score_data.get("existence", {})
    identity  = score_data.get("identity", {})
    classif   = score_data.get("classification", {})

    _process_checks(EXISTENCE_CHECKS, existence)
    _process_checks(IDENTITY_CHECKS, identity)
    _process_checks(CLASSIFICATION_CHECKS, classif)

    # ── Build patch payload ──────────────────────────────────────────────
    patch = {"custom_fields": {}}

    if "score" in existence:
        patch["custom_fields"]["confidence_existence"] = existence["score"]
    if "score" in identity:
        patch["custom_fields"]["confidence_identity"] = identity["score"]
    if "score" in classif:
        patch["custom_fields"]["confidence_classification"] = classif["score"]
    if "total" in score_data:
        patch["custom_fields"]["confidence_total"] = score_data["total"]

    # always stamp last_seen on every scoring pass
    patch["custom_fields"]["last_seen"] = datetime.now(timezone.utc).date().isoformat()

    if tag_ids:
        patch["tags"] = tag_ids

    # ── Patch the device ─────────────────────────────────────────────────
    r = requests.patch(f"{API}/dcim/devices/{device_id}/", json=patch, **REQ)
    if r.status_code == 200:
        total = score_data.get("total", "?")
        print(f"    ✔ Applied scoring to device {device_id} (total: {total})")
    else:
        print(f"    ✘ Failed to apply scoring to device {device_id}: {r.status_code} {r.text[:200]}")