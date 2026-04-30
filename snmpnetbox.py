import asyncio
import ipaddress
from pysnmp.hlapi.v3arch.asyncio import *
import os
from dotenv import load_dotenv
from db import init_snmp_db, save_snmp_results
import math

# load environment variables
load_dotenv()
oids = {
    "Hostname": os.getenv("SNMP_OID_HOSTNAME"),
    "Description": os.getenv("SNMP_OID_DESCRIPTION"),
    "Uptime": os.getenv("SNMP_OID_UPTIME"),
    "Interfaces": os.getenv("SNMP_OID_INTERFACES")
}

ipSearch = os.getenv("SNMP_TARGET_SUBNET")
snmpCommName = os.getenv("SNMP_COMMUNITY")

snmpCommVersion = 1 if os.getenv("SNMP_VERSION") == "2c" else 0

# scans the subnetfor snmp information
async def scan_subnet(snmpEngine, hosts):
    batch_size = 100 # search hosts in baches of 50
    total_batches = math.ceil(len(hosts) / batch_size)
    results = []

    for i in range(0, len(hosts), batch_size):
        batch = hosts[i:i + batch_size]
        batch_num = i // batch_size + 1
        ip_range = f"{batch[0]} - {batch[-1]}"

        print(f"[snmp] Scanning batch {batch_num}/{total_batches} ({ip_range})")
        batch_results = await asyncio.gather(*[query(snmpEngine, ip) for ip in batch])
        found = [r for r in batch_results if r is not None]

        if found:
            for r in found:
                print(f"[snmp] Found device: {r['ip']}")
        else:
            print(f"[snmp] No devices found in {ip_range}")
        results.extend(batch_results)
        await asyncio.sleep(0.1)

    return [r for r in results if r is not None]

# initializes snmp engine and calls scan_subnet and saves it to the database
async def run():
    # Initializes database
    print("[snmp] Initializing the snmp database")
    init_snmp_db()

    # sets up snmp engine, subnet, and hosts in subnet
    snmpEngine = SnmpEngine()
    subnet = ipaddress.ip_network(str(ipSearch))
    hosts = list(subnet.hosts())

    # hosts with snmp information
    results = await scan_subnet(snmpEngine, hosts)

    snmpEngine.close_dispatcher()
    print(f"[snmp] {len(results)} device(s) found")
    print("[snmp] Saving results into snmp database")
    save_snmp_results(results)

# asks host if it has snmp information
async def query(snmpEngine, ip):
    try:
        object_types = [ObjectType(ObjectIdentity(oid)) for oid in oids.values()]
        iterator = get_cmd(
            snmpEngine,
            CommunityData(str(snmpCommName), mpModel=snmpCommVersion),
            await UdpTransportTarget.create((str(ip), 161), timeout=2, retries=1),
            ContextData(),
            *object_types,
        )
        errorIndication, errorStatus, errorIndex, varBinds = await iterator

        if errorIndication:
            pass
        elif errorStatus:
            print("{} at {}".format(
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            ))
        else:
            row = {"ip": str(ip)}
            for label, varBind in zip(oids.keys(), varBinds):
                row[label] = varBind[1].prettyPrint()
            return row
    except Exception as e:
        return None
    return None

if __name__ == "__main__":
    asyncio.run(run())
