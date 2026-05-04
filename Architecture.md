# Architecture

This document explains how Automation Station fits together — what runs in
what order, what each file is responsible for, and where to look when
something breaks.

The first half is a high-level overview for someone new to the codebase. The
second half goes deeper into individual components for maintainers and
contributors.

---

## Part 1: High-Level Overview

### What this thing is

Automation Station is a network discovery pipeline. It scans a subnet, gathers
evidence about each device from multiple sources, scores how confident it is
about what each device is, and pushes everything into NetBox with that
confidence visible.

The whole pipeline runs as a single sequential job from `main.py`. There's no
background worker, no message queue, no microservices — just one Python process
that walks through the steps top to bottom.

### The pipeline at a glance

```
┌────────────┐    ┌──────────┐    ┌──────────┐    ┌─────────┐
│   Nmap     │───▶│   SNMP   │───▶│   DHCP   │───▶│   DNS   │
│  (scan)    │    │  (poll)  │    │  (Kea)   │    │ (lookup)│
└────────────┘    └──────────┘    └──────────┘    └─────────┘
       │                │                │             │
       └────────────────┴────────┬───────┴─────────────┘
                                 ▼
                         ┌────────────────┐
                         │  SQLite DB     │
                         │ (evidence log) │
                         └────────────────┘
                                 │
                                 ▼
                         ┌────────────────┐
                         │  Correlation   │
                         │  (one device   │
                         │   per IP)      │
                         └────────────────┘
                                 │
                                 ▼
                         ┌────────────────┐
                         │    Scoring     │
                         │ (3 categories) │
                         └────────────────┘
                                 │
                                 ▼
                         ┌────────────────┐
                         │    NetBox      │
                         │ (push + tag)   │
                         └────────────────┘
                                 │
                                 ▼
                         ┌────────────────┐
                         │  Email report  │
                         │ (low scorers)  │
                         └────────────────┘
```

### What each file does (one-liner version)

| File | Purpose |
|------|---------|
| `main.py` | Pipeline orchestrator. Runs every step in order. |
| `launcher.py` | Friendly wrapper around `main.py` with config detection and interactive setup. |
| `runner.py` | Calls the `nmap` system binary and returns XML output. |
| `parser.py` | Parses nmap XML into Python dicts. |
| `cidr.py` | Validates CIDR strings before passing to nmap. |
| `snmpnetbox.py` | Performs the SNMP scan and stores results in SQLite. |
| `dhcp.py` | Queries the Kea DHCP REST API for active leases. |
| `dns_lookup.py` | Forward and reverse DNS lookups via Python stdlib. |
| `ieeething/oui_lookup.py` | Maps a MAC address prefix to a manufacturer name. |
| `db.py` | SQLite schema, inserts, and reads. |
| `models/evidence.py` | `EvidenceRecord` dataclass — one observation from one source. |
| `models/device_record.py` | `DeviceRecord` dataclass — combined evidence per device. |
| `models/scoring_result.py` | `ScoringResult` and `TestResult` dataclasses. |
| `models/correlate.py` | Groups evidence by IP into device records. |
| `scoring/existence.py` | Scores whether a device is really there. |
| `scoring/identity.py` | Scores how confident we are it's the device we think it is. |
| `scoring/classification.py` | Scores how well we can classify what kind of device it is. |
| `scoring/system.py` | Combines the three category scores into one overall score. |
| `netbox_integration.py` | Creates devices, IPs, interfaces in NetBox via API. |
| `netbox_scoring.py` | Patches confidence scores, tags, and timestamps onto NetBox devices. |
| `netbox_cleanup.py` | Deletes everything the pipeline created. Used for resets during testing. |
| `netbox_api_tester.py` | Standalone NetBox API connectivity check. |
| `mail.py` | Sends an email report listing devices below `MAIL_REPORT_THRESHOLD`. |
| `validate_env.py` | Checks required environment variables on startup. |
| `schema.py` | Builds the JSON output document for the standalone `scan.py` command. |
| `scan.py` | A simpler standalone scanner used for one-off scans without the full pipeline. |

### Where things live on disk

```
AutomationStation/
├── main.py                      ← entry point
├── launcher.py                  ← friendly wrapper
├── pyproject.toml               ← package definition
├── .env                         ← config (not in git)
├── scan_results.db              ← SQLite (not in git)
│
├── models/                      ← data shapes (no logic)
├── scoring/                     ← scoring rules
├── collectors/                  ← evidence collectors
├── ieeething/                   ← OUI lookup + the IEEE CSV
└── netbox/                      ← (legacy, deleted in main)
```

### How to find your way around

If you're trying to figure out where to make a change, this map should help:

- **Adding a new evidence source?** Look at `snmpnetbox.py` or `dhcp.py` as a
  template. Your collector needs to produce `EvidenceRecord` instances and
  feed them into the evidence list in `main.py`.
- **Changing what a score check does?** It's in one of the three files under
  `scoring/`. Each category has its own file with its own weights.
- **Changing what gets pushed to NetBox?** `netbox_integration.py` for the
  device creation, `netbox_scoring.py` for the scoring metadata.
- **Adding a new NetBox custom field?** `netbox_scoring.py`, the
  `CUSTOM_FIELDS` list near the top.
- **Tweaking how the launcher works?** `launcher.py` — it's self-contained.
- **Pipeline order?** `main.py`, the `main()` function. Steps are numbered in
  the print statements (`[1] Ping sweep`, `[2] Deep scan`, etc.).

---

## Part 2: Maintainer Reference

### Pipeline execution order

The `main()` function in `main.py` runs these steps in this exact order:

1. **`validate_env()`** — checks required env vars are set, fails fast if not.
2. **`init_snmp_db()`** — creates SQLite tables if they don't exist.
3. **`run_scan(SUBNET)`** — runs nmap twice: a ping sweep, then a deep scan
   on the live IPs.
4. **`save_discovered_hosts(hosts)`** — writes nmap results to the
   `discovered_hosts` table.
5. **`asyncio.run(run_snmp())`** — does the SNMP poll across the subnet, saves
   results to the `snmp_results` table.
6. **`dhcp_scan()`** — queries Kea, saves leases to the `dhcp_results` table.
7. **DNS resolution loop** — reverse lookups every live IP, attaches the
   hostname to the host dict in memory.
8. **OUI enrichment loop** — for any host without a vendor from nmap, look it
   up by MAC prefix.
9. **Evidence assembly** — converts everything (nmap, snmp, dhcp, dns) into
   `EvidenceRecord` instances.
10. **`correlate_evidence(evidence)`** — groups records by IP into
    `DeviceRecord` instances.
11. **Scoring loop** — `ScoringSystem().score(device)` for each device.
12. **`check_netbox()`** — verifies NetBox is reachable before pushing.
13. **`ensure_scoring_fields()`** — creates custom fields in NetBox if missing.
14. **`push_hosts_to_netbox(hosts)`** — creates/updates devices, IPs, interfaces.
15. **Per-device scoring patch** — looks up each device by name in NetBox and
    PATCHes confidence scores, tags, timestamps onto it.
16. **`send_issue_report(scored_results)`** — emails any devices scoring below
    `MAIL_REPORT_THRESHOLD`.

If a step fails, downstream steps will usually still run with whatever data
they have. This is intentional — partial results are better than none. The
exception is `check_netbox()`: if NetBox isn't reachable, the push and scoring
steps are skipped entirely.

### The scoring model

Three independent category scores are calculated, each on a 0–100 scale:

- **Existence** — Is this device actually there? Backed by SNMP responses,
  open ports, active DHCP leases, and DNS resolution.
- **Identity** — Are we confident it's *this specific* device and not
  something else with the same IP? Backed by MAC matches, hostname agreement
  across sources, and conflict detection.
- **Classification** — Can we say what *kind* of device it is? Backed by SNMP
  sysObjectID, nmap service profile, OUI manufacturer, and DNS naming hints.

The overall score is the average of the three. Each individual check produces
a `TestResult` with a weight, a pass/fail, and an explanation. These are what
become the color-coded tags in NetBox.

The weights are deliberately not normalized — a single category can hit 100
even if not every check passes, because some sources (SNMP, DHCP) provide
strong evidence on their own.

### Data flow shapes

The three core dataclasses (in `models/`) and how they relate:

```
        EvidenceRecord                  DeviceRecord                 ScoringResult
        ──────────────                  ────────────                 ─────────────
        • source                        • ip                         • existence_score
        • ip                            • mac                        • identity_score
        • mac                  ──┐      • hostnames (set)            • classification_score
        • hostname               │      • manufacturer    ──┐        • overall_score
        • manufacturer           ├─▶    • evidence (list) ◀─┘   ──▶  • tests (list of
        • attributes (dict)      │                                      TestResult)
                                 │
        many per device  ────────┘      one per real device          one per device

        ── created by collectors ──     ── created by correlate ──   ── created by ScoringSystem ──
```

Many `EvidenceRecord`s collapse into one `DeviceRecord`. The `DeviceRecord`
gets passed to the scoring engine which produces a `ScoringResult`.

### Database schema (actual)

Three tables in `scan_results.db`:

```sql
discovered_hosts (ip PK, mac, vendor, os_name, open_ports JSON, scan_time)
snmp_results     (ip PK, Hostname, Description, Uptime, Interfaces, last_seen)
dhcp_results     (ip PK, mac, hostname, expiry, last_seen)
```

Note: the README's "Database Architecture" section describes a more elaborate
schema (Devices / Scan_Results / Confidence_History tables) that represents
the long-term goal. The code currently uses the simpler three-table layout
above. Either is valid; future refactoring may bring them into alignment.

### NetBox writes

The pipeline writes to NetBox in two passes. This separation matters:

**Pass 1: `push_hosts_to_netbox()`** — creates the device itself plus its
prerequisites. Get-or-create pattern for everything:

- `dcim/sites/` — one site, "PSL Lab"
- `dcim/manufacturers/` — one per unique vendor seen
- `dcim/device-roles/` — inferred from open ports (e.g., port 53 → "DNS Server")
- `dcim/device-types/` — one per (manufacturer, OS name) pair
- `dcim/devices/` — the device itself
- `dcim/interfaces/` — a default `eth0`
- `ipam/ip-addresses/` — assigned to the interface, set as primary IPv4

**Pass 2: `apply_scoring()`** — PATCHes scoring metadata onto the existing
device. Custom fields and tags only; doesn't touch the device's core record.

The two-pass design means a device can be pushed without a score (and vice
versa, if the device already exists from a previous run). It also means
scoring can be re-run independently without re-creating devices.

### NetBox version compatibility notes

This was developed against NetBox 4.5.2. A few things to be aware of:

- **API tokens**: NetBox 4.5 defaults to v2 tokens (Bearer format). The code
  uses `Token` header auth which requires a v1 token. If auth fails, check
  the token type in the NetBox UI.
- **`role` vs `device_role`**: Older NetBox used `device_role` as the field
  name; 4.x renamed it to `role`. The code uses `role`.
- **`primary_mac_address`**: Added in 4.x. Not used heavily here but
  referenced in `netbox_integration.py`.
- **Custom field types**: `datetime` (used for `last_scanned`) requires
  NetBox 4.x. Won't work on 3.x.

### Configuration philosophy

Everything that can vary by deployment lives in `.env`. The launcher's
config search path (`./`, `~/.config/`, `/etc/`) lets the same binary work
in three contexts:

- Developer running locally → `.env` in working directory
- IT user on a workstation → `~/.config/automation-station/config.env`
- Server / systemd deployment → `/etc/automation-station/config.env`

`validate_env.py` runs first thing in the pipeline so missing config fails
loudly instead of breaking three steps in.

### Privilege model

`nmap` needs raw socket access for SYN scans. Three options were considered:

1. Run the whole pipeline as root → unacceptable, NetBox API tokens shouldn't
   live in a process owned by root.
2. Use `sudo` for nmap calls → fragile under systemd, requires a sudoers
   entry, doesn't compose well.
3. **Grant nmap Linux capabilities directly** → chosen. One-time setup:

   ```bash
   sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
   ```

   The pipeline then runs as a normal user and nmap has just the network
   capabilities it needs.

`runner.py` passes `--privileged` to nmap on every call, which tells nmap to
trust that it has the capabilities even though it's not running as root.

### Known issues and design quirks

A few things that aren't bugs but might surprise someone reading the code:

- **`192.168.202.225` self-scan**: When the pipeline runs on the same host as
  NetBox, nmap can't see its own MAC via ARP. The host appears with `mac:
  null` and gets a lower identity score than its actual reliability. This is
  a quirk of self-scanning, not a bug.
- **DHCP pool empty results**: If the pool returns 0 leases, every device's
  identity score loses up to 30 points. Make sure the Kea pool range in
  `.env` actually overlaps with your scan subnet.
- **NetBox device naming**: Devices are named by DNS first, then nmap
  hostname, then a synthesized `host-{ip-with-dashes}`. Renaming a device in
  NetBox manually will cause the next scan to create a duplicate.
- **Two-write order matters**: Push-then-score relies on the device existing
  in NetBox before scoring runs. If `push_hosts_to_netbox` fails for a host,
  scoring will print "Could not find device" and skip it.

### Adding a new evidence source

If you want to add, say, a SYSLOG-based collector:

1. Create the collector that produces `EvidenceRecord` instances with
   `source="syslog"` and whatever attributes are useful.
2. Wire it into `main.py` between the existing collectors and the evidence
   assembly step.
3. Update one or more files in `scoring/` to look for `source == "syslog"`
   and `attributes["whatever"]`. Add a new `TestResult` for the new check.
4. Add the corresponding test name to `TEST_NAME_MAP` in `main.py` so it
   maps to a tag-friendly key.
5. Add the tag definition to the appropriate `_CHECKS` dict in
   `netbox_scoring.py` so a tag gets created.

The existing collectors in `collectors/nmap_collector.py` and
`collectors/snmp_collector.py` are class-based templates worth following.

### Adding a new NetBox custom field

In `netbox_scoring.py`:

1. Add an entry to `CUSTOM_FIELDS` (name, label, type).
2. In `apply_scoring()`, add a line to populate
   `patch["custom_fields"][your_field_name]`.

That's it — `ensure_scoring_fields()` will auto-create the field on the next
run, and every device will start getting the value.
