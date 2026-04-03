#!/usr/bin/env python3
import os
import sys
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
    from dotenv import load_dotenv
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip3 install requests python-dotenv rich")
    sys.exit(1)

load_dotenv()

NETBOX_URL = os.getenv("NETBOX_URL", "").rstrip("/")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN", "")

if not NETBOX_URL or not NETBOX_TOKEN:
    print("ERROR: Set NETBOX_URL and NETBOX_TOKEN in your .env file.")
    sys.exit(1)

API_BASE = f"{NETBOX_URL}/api"
HEADERS = {
    "Authorization": f"Token {NETBOX_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

console = Console()

ENDPOINTS = {
    "DCIM (Data Center Infrastructure)": [
        ("Sites",                "/dcim/sites/"),
        ("Regions",              "/dcim/regions/"),
        ("Site Groups",          "/dcim/site-groups/"),
        ("Locations",            "/dcim/locations/"),
        ("Racks",                "/dcim/racks/"),
        ("Rack Roles",           "/dcim/rack-roles/"),
        ("Rack Reservations",    "/dcim/rack-reservations/"),
        ("Device Types",         "/dcim/device-types/"),
        ("Manufacturers",        "/dcim/manufacturers/"),
        ("Device Roles",         "/dcim/device-roles/"),
        ("Platforms",            "/dcim/platforms/"),
        ("Devices",              "/dcim/devices/"),
        ("Device Bays",          "/dcim/device-bays/"),
        ("Interfaces",           "/dcim/interfaces/"),
        ("Front Ports",          "/dcim/front-ports/"),
        ("Rear Ports",           "/dcim/rear-ports/"),
        ("Console Ports",        "/dcim/console-ports/"),
        ("Console Server Ports", "/dcim/console-server-ports/"),
        ("Power Ports",          "/dcim/power-ports/"),
        ("Power Outlets",        "/dcim/power-outlets/"),
        ("Power Feeds",          "/dcim/power-feeds/"),
        ("Power Panels",         "/dcim/power-panels/"),
        ("Cables",               "/dcim/cables/"),
        ("Virtual Chassis",      "/dcim/virtual-chassis/"),
        ("Inventory Items",      "/dcim/inventory-items/"),
    ],
    "IPAM (IP Address Management)": [
        ("VRFs",            "/ipam/vrfs/"),
        ("Route Targets",   "/ipam/route-targets/"),
        ("RIRs",            "/ipam/rirs/"),
        ("Aggregates",      "/ipam/aggregates/"),
        ("Roles",           "/ipam/roles/"),
        ("Prefixes",        "/ipam/prefixes/"),
        ("IP Ranges",       "/ipam/ip-ranges/"),
        ("IP Addresses",    "/ipam/ip-addresses/"),
        ("VLANs",           "/ipam/vlans/"),
        ("VLAN Groups",     "/ipam/vlan-groups/"),
        ("Services",        "/ipam/services/"),
        ("ASNs",            "/ipam/asns/"),
    ],
    "Virtualization": [
        ("Cluster Types",    "/virtualization/cluster-types/"),
        ("Cluster Groups",   "/virtualization/cluster-groups/"),
        ("Clusters",         "/virtualization/clusters/"),
        ("Virtual Machines", "/virtualization/virtual-machines/"),
        ("VM Interfaces",    "/virtualization/interfaces/"),
        ("VM Disks",         "/virtualization/virtual-disks/"),
    ],
    "Circuits": [
        ("Circuit Types",        "/circuits/circuit-types/"),
        ("Circuits",             "/circuits/circuits/"),
        ("Circuit Terminations", "/circuits/circuit-terminations/"),
        ("Providers",            "/circuits/providers/"),
        ("Provider Networks",    "/circuits/provider-networks/"),
    ],
    "Tenancy": [
        ("Tenant Groups",       "/tenancy/tenant-groups/"),
        ("Tenants",             "/tenancy/tenants/"),
        ("Contacts",            "/tenancy/contacts/"),
        ("Contact Roles",       "/tenancy/contact-roles/"),
        ("Contact Groups",      "/tenancy/contact-groups/"),
        ("Contact Assignments", "/tenancy/contact-assignments/"),
    ],
    "Extras": [
        ("Tags",            "/extras/tags/"),
        ("Config Contexts", "/extras/config-contexts/"),
        ("Custom Fields",   "/extras/custom-fields/"),
        ("Custom Links",    "/extras/custom-links/"),
        ("Webhooks",        "/extras/webhooks/"),
        ("Journal Entries", "/extras/journal-entries/"),
        ("Object Changes",  "/extras/object-changes/"),
        ("Saved Filters",   "/extras/saved-filters/"),
        ("Scripts",         "/extras/scripts/"),
        ("Reports",         "/extras/reports/"),
    ],
    "Users": [
        ("Users",       "/users/users/"),
        ("Groups",      "/users/groups/"),
        ("Tokens",      "/users/tokens/"),
        ("Permissions", "/users/permissions/"),
    ],
    "Wireless": [
        ("Wireless LANs",       "/wireless/wireless-lans/"),
        ("Wireless LAN Groups", "/wireless/wireless-lan-groups/"),
        ("Wireless Links",      "/wireless/wireless-links/"),
    ],
}


def get(path, params=None):
    try:
        r = requests.get(
            f"{API_BASE}{path}",
            headers=HEADERS,
            params=params or {"limit": 5},
            timeout=10,
            verify=False,
        )
        return r.status_code, r.json() if r.content else {}
    except requests.exceptions.ConnectionError:
        return 0, {"error": "Connection refused / unreachable"}
    except requests.exceptions.Timeout:
        return -1, {"error": "Timeout"}
    except Exception as e:
        return -2, {"error": str(e)}


def status_icon(code):
    if code == 200:  return "[green]✔ 200[/green]"
    if code == 403:  return "[yellow]✘ 403 Forbidden[/yellow]"
    if code == 404:  return "[red]✘ 404 Not Found[/red]"
    if code == 401:  return "[red]✘ 401 Unauthorized[/red]"
    if code == 0:    return "[red]✘ No Connection[/red]"
    if code == -1:   return "[yellow]⏱ Timeout[/yellow]"
    return f"[red]✘ {code}[/red]"


def test_connection():
    console.rule("[bold cyan]1. Connectivity & Authentication[/bold cyan]")
    code, data = get("/")
    if code == 200:
        rprint(f"  [green]✔ Connected to NetBox at {NETBOX_URL}[/green]")
    else:
        rprint(f"  [red]✘ Could not reach {NETBOX_URL}[/red]  →  {data}")
        sys.exit(1)
    code2, _ = get("/users/tokens/", {"limit": 1})
    if code2 == 200:
        rprint("  [green]✔ API token is valid[/green]")
    elif code2 == 403:
        rprint("  [yellow]⚠ Token valid but lacks Users permission[/yellow]")
    else:
        rprint(f"  [red]✘ Token issue ({code2})[/red]")


def test_netbox_version():
    console.rule("[bold cyan]2. NetBox Version & Status[/bold cyan]")
    code, data = get("/status/")
    if code == 200 and isinstance(data, dict):
        table = Table(show_header=False, box=None, padding=(0, 2))
        for k, v in data.items():
            table.add_row(f"[dim]{k}[/dim]", str(v))
        console.print(table)
    else:
        rprint(f"  [yellow]Status endpoint returned {code}[/yellow]")


def test_all_endpoints():
    console.rule("[bold cyan]3. Endpoint Availability Scan[/bold cyan]")
    results = {}
    for category, endpoints in ENDPOINTS.items():
        cat_results = []
        for name, path in endpoints:
            code, data = get(path, {"limit": 1})
            count = data.get("count", "?") if code == 200 and isinstance(data, dict) else None
            cat_results.append((name, path, code, count))
        results[category] = cat_results

    for category, rows in results.items():
        table = Table(title=f"[bold]{category}[/bold]", show_header=True,
                      header_style="bold magenta", expand=True)
        table.add_column("Endpoint", style="cyan", no_wrap=True)
        table.add_column("Path", style="dim")
        table.add_column("Status", justify="center")
        table.add_column("Record Count", justify="right")
        for name, path, code, count in rows:
            table.add_row(name, path, status_icon(code), str(count) if count is not None else "-")
        console.print(table)
        console.print()
    return results


def test_key_data():
    console.rule("[bold cyan]4. Sample Data from Key Endpoints[/bold cyan]")
    samples = [
        ("Sites",        "/dcim/sites/"),
        ("Devices",      "/dcim/devices/"),
        ("IP Addresses", "/ipam/ip-addresses/"),
        ("Prefixes",     "/ipam/prefixes/"),
        ("VLANs",        "/ipam/vlans/"),
        ("Interfaces",   "/dcim/interfaces/"),
    ]
    for label, path in samples:
        code, data = get(path, {"limit": 5})
        if code != 200 or not isinstance(data, dict):
            rprint(f"  [yellow]{label}: skipped ({code})[/yellow]")
            continue
        results = data.get("results", [])
        total = data.get("count", 0)
        if not results:
            rprint(f"  [dim]{label}: 0 records[/dim]")
            continue
        rprint(f"\n  [bold]{label}[/bold] — {total} total, showing up to 5:")
        table = Table(show_header=True, header_style="bold blue", expand=True)
        first = results[0]
        cols = [k for k in ["id", "name", "display", "address", "prefix", "status",
                             "family", "site", "role", "device_type"] if k in first]
        if not cols:
            cols = list(first.keys())[:5]
        for c in cols:
            table.add_column(c, overflow="fold")
        for item in results:
            row = []
            for c in cols:
                val = item.get(c, "")
                if isinstance(val, dict):
                    val = val.get("display") or val.get("name") or val.get("label") or str(val)
                row.append(str(val) if val is not None else "")
            table.add_row(*row)
        console.print(table)


def test_search():
    console.rule("[bold cyan]5. Global Search[/bold cyan]")
    code, data = get("/search/", {"q": "test", "limit": 5})
    if code == 200:
        results = data.get("results", []) if isinstance(data, dict) else []
        rprint(f"  [green]✔ Search endpoint available[/green] — 'test' returned {len(results)} result(s)")
    elif code == 404:
        rprint("  [yellow]Global search not available (older NetBox version?)[/yellow]")
    else:
        rprint(f"  [yellow]Search returned {code}[/yellow]")


def test_filtering():
    console.rule("[bold cyan]6. Filtering & Query Capabilities[/bold cyan]")
    tests = [
        ("Filter devices by status=active",  "/dcim/devices/",      {"status": "active", "limit": 3}),
        ("Filter IPs by family=4 (IPv4)",    "/ipam/ip-addresses/", {"family": "4", "limit": 3}),
        ("Filter IPs by family=6 (IPv6)",    "/ipam/ip-addresses/", {"family": "6", "limit": 3}),
        ("Filter prefixes by status=active", "/ipam/prefixes/",     {"status": "active", "limit": 3}),
        ("Devices brief format",             "/dcim/devices/",      {"brief": True, "limit": 3}),
    ]
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Test")
    table.add_column("Status", justify="center")
    table.add_column("Results Returned", justify="right")
    for label, path, params in tests:
        code, data = get(path, params)
        count = len(data.get("results", [])) if code == 200 and isinstance(data, dict) else "-"
        table.add_row(label, status_icon(code), str(count))
    console.print(table)


def test_write_capability():
    console.rule("[bold cyan]7. Write Capability Check (HTTP OPTIONS)[/bold cyan]")
    paths = ["/dcim/sites/", "/ipam/ip-addresses/", "/dcim/devices/"]
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Endpoint")
    table.add_column("Allowed Methods")
    for path in paths:
        try:
            r = requests.options(
                f"{API_BASE}{path}",
                headers=HEADERS,
                timeout=8,
                verify=False,
            )
            allowed = r.headers.get("Allow", "unknown")
        except Exception as e:
            allowed = f"Error: {e}"
        table.add_row(path, allowed)
    console.print(table)


def test_pagination():
    console.rule("[bold cyan]8. Pagination Test[/bold cyan]")
    code, data = get("/ipam/ip-addresses/", {"limit": 2, "offset": 0})
    if code == 200 and isinstance(data, dict):
        rprint(f"  Total records : {data.get('count', 0)}")
        rprint(f"  Page size     : {len(data.get('results', []))}")
        rprint(f"  Next URL      : {data.get('next') or 'None'}")
        rprint(f"  Prev URL      : {data.get('previous') or 'None'}")
        rprint("  [green]✔ Pagination working correctly[/green]")
    else:
        rprint(f"  [yellow]Skipped — returned {code}[/yellow]")


def summary(results):
    console.rule("[bold cyan]Summary[/bold cyan]")
    total = ok = forbidden = missing = 0
    for rows in results.values():
        for _, _, code, _ in rows:
            total += 1
            if code == 200:   ok += 1
            elif code == 403: forbidden += 1
            elif code == 404: missing += 1
    rprint(Panel(
        f"[green]✔ Accessible  : {ok}[/green]\n"
        f"[yellow]⚠ Forbidden   : {forbidden}[/yellow]\n"
        f"[red]✘ Not Found   : {missing}[/red]\n"
        f"[dim]  Other/Error : {total - ok - forbidden - missing}[/dim]\n"
        f"[bold]  Total       : {total}[/bold]",
        title="[bold white]API Endpoint Report[/bold white]",
        expand=False,
    ))


def main():
    console.print(Panel.fit(
        f"[bold cyan]NetBox API Capability Tester[/bold cyan]\n"
        f"[dim]Target : {NETBOX_URL}[/dim]\n"
        f"[dim]Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
        border_style="cyan",
    ))
    test_connection()
    test_netbox_version()
    endpoint_results = test_all_endpoints()
    test_key_data()
    test_search()
    test_filtering()
    test_write_capability()
    test_pagination()
    summary(endpoint_results)


if __name__ == "__main__":
    main()