import sqlite3

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