from __future__ import annotations

import json
import os

from collectors.nmap_collector import NmapCollector
from collectors.snmp_collector import SNMPCollector
from models.correlate import correlate_evidence
from scoring.system import ScoringSystem
from netbox.client import NetBoxClient
from netbox.sync import NetBoxSync

def main() -> None:
    nmap_collector = NmapCollector()
    snmp_collector = SNMPCollector(env_file="env-2")
    #path fix hopefully
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    nmap_results_path = os.path.join(BASE_DIR, "results.json")#nmap

    env_path = os.path.join(BASE_DIR, "env-2")

    print("[MAIN] Using env file:", env_path)

    snmp_collector = SNMPCollector(env_file=env_path)

    #use an existing saved results file
    nmap_evidence = nmap_collector.collect_from_file(nmap_results_path)
    snmp_evidence = snmp_collector.collect_from_scan()

    #run a live scan instead
    #evidence = nmap_collector.collect_from_scan("192.168.202.0/24", top_ports=1000)

    all_evidence= []
    all_evidence.extend(nmap_evidence)
    all_evidence.extend(snmp_evidence)

    devices = correlate_evidence(all_evidence)
    engine = ScoringSystem()

    #netbox configuration
    netbox_url = "192.168.202.225"
    netbox_token = "5m1pdhJeYyu2JMnVxugCeHutPLA42UXyludQrpkz"

    nb_client = NetBoxClient(netbox_url, netbox_token)
    nb_sync = NetBoxSync(nb_client)

    all_results = []

    for device in devices:
        result = engine.score(device)

        all_results.append({
            "device": device.to_dict(),
            "score": result.to_dict(),
        })

        try:
            nb_sync.push_result(device, result)
        except Exception as e:
            print(f"[ERROR] Failed syncing device ip={device.ip}: {e}")

    print(json.dumps(all_results, indent=2))


if __name__ == "__main__":
    main()