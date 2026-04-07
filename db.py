import sqlite3
import json

DB_PATH = 'scan_results.db'

# SNMP
def init_snmp_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS snmp_results (
        ip TEXT PRIMARY KEY,
        Hostname TEXT,
        Description TEXT,
        Uptime TEXT,
        Interfaces TEXT,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS discovered_hosts (
        ip TEXT PRIMARY KEY,
        mac TEXT,
        vendor TEXT,
        os_name TEXT,
        open_ports TEXT,
        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_snmp_results(results):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for ip_found in results:
        cursor.execute('''
            INSERT OR REPLACE INTO snmp_results (ip, Hostname, Description, Uptime, Interfaces)
            VALUES (:ip, :Hostname, :Description, :Uptime, :Interfaces)
        ''', ip_found)
    conn.commit()
    conn.close()
    print(f"Saved {len(results)} ip addresses into {DB_PATH}")

# DHCP
def init_dhcp_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dhcp_results (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            hostname TEXT,
            expiry TEXT,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_dhcp_results(results):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for device in results:
        cursor.execute('''
            INSERT OR REPLACE INTO dhcp_results (ip, mac, hostname, expiry)
            VALUES (:ip, :mac, :hostname, :expiry)
        ''', device)
    conn.commit()
    conn.close()
    print(f"Saved {len(results)} DHCP leases into {DB_PATH}")


def save_discovered_hosts(hosts):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for h in hosts:
        open_ports = [p for p in h.get("ports", []) if p.get("state") == "open"]
        cursor.execute('''
            INSERT OR REPLACE INTO discovered_hosts (ip, mac, vendor, os_name, open_ports)
            VALUES (?, ?, ?, ?, ?)
        ''', (h.get("ip"), h.get("mac"), h.get("vendor"),
              (h.get("os") or {}).get("name"), json.dumps(open_ports)))
    conn.commit()
    conn.close()
    print(f"Saved {len(hosts)} hosts into {DB_PATH}")