import asyncio
import ipaddress
from pysnmp.hlapi.v3arch.asyncio import *
from pysnmp import debug
import os
from dotenv import load_dotenv, dotenv_values
from db import init_snmp_db, save_snmp_results 


load_dotenv('.env')
oids = {
    "Hostname": os.getenv("SNMP_OID_HOSTNAME"),
    "Description": os.getenv("SNMP_OID_DESCRIPTION"),
    "Uptime": os.getenv("SNMP_OID_UPTIME"),
    "Interfaces": os.getenv("SNMP_OID_INTERFACES")
}

ipSearch = os.getenv("SNMP_TARGET_SUBNET")
snmpCommName = os.getenv("SNMP_COMMUNITY")

if (os.getenv("SNMP_VERSION") == "2c"): 
    snmpCommVersion = 1 
else: 
    snmpCommVersion = 0


async def run():
    snmpEngine = SnmpEngine()
    subnet = ipaddress.ip_network(str(ipSearch))
    hosts = list(subnet.hosts()) 

    batch_size = 50
    results = []

    init_snmp_db()

    for i in range(0, len(hosts), batch_size): 
        batch = hosts[i:i + batch_size]
        batch_results = await asyncio.gather(*[query(snmpEngine, ip) for ip in batch])
        results.extend(batch_results)  
        await asyncio.sleep(0.1) 

    snmpEngine.close_dispatcher()
    results = [r for r in results if r is not None]
    save_snmp_results(results)
    print(results) 

async def query(snmpEngine, ip):
    try:
        object_types = [ObjectType(ObjectIdentity(oid)) for oid in oids.values()]
        iterator = get_cmd(
            snmpEngine,
            CommunityData(str(snmpCommName), mpModel=snmpCommVersion),
            await UdpTransportTarget.create((str(ip), 161), timeout=2, retries=0),
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
            print(f"Found SNMP device: {ip}")
            return row
    except Exception:
        pass
    return None

if __name__ == "__main__":
    asyncio.run(run())