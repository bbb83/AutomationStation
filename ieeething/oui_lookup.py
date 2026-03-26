# takes oui(first 24 bits) from mac address and compares to ieee database to give manufacturer

import csv
from pathlib import Path
from models.evidence import EvidenceRecord

class OUIlookup:
    def __init__(self, oui_file:str):
        self.oui_map = {}
        self.load_file(oui_file)

        def load_file(self, oui_file:str)-> None:
            #load ieee oui from csv
            #format should be: prefix, manufacturer
                            #  00:11:22, Cisco for example
            path = Path(oui_file)

            if not path.exists():
                raise FileNotFoundError(f"Couldn't find OUI file: {oui_file}")
            
            with open(path, newline="", encoding="utf-8")as f:
                reader = csv.reader(f)

                for row in reader:
                    if len(row) < 2:
                        continue

                    prefix = self.normalize_oui(row[0])
                    manufacturer = row[1].strip()

                    if prefix:
                        self.oui_map[prefix]= manufacturer

def normalize_mac(self, mac:str) -> str:
    "normalizes the mac to all uppercase and no seperators"
    return mac.upper().replace("-","").replace(":","")

def normalize_oui(self, oui:str) -> str:
    "normalizes OUI to just first 6 hex chars"
    return self.normalize_mac(oui)[:6]

def lookup(self, mac:str) -> dict | None:
    #looks up manufacturer from mac
    #returns: "manufacturer_name": "", "oui_prefix": ""
    if not mac:
        return None
    
    normalized = self.normalize_mac(mac)
    prefix = normalized[:6]
    manufacturer = self.oui_map.get(prefix)

    if manufacturer:
        return{
            "manufacturer_name": manufacturer,
            "oui_prefix": prefix
        }
    
    return None

def addto_evidence(self, ev: EvidenceRecord) -> EvidenceRecord:
    #adds oui manufacturer info to EvidenceRecord
    if not ev.mac:
        return ev
    
    result = self.lookup(ev.mac)

    if result:
        ev.manufacturer = result["manufacturer_name"]
        ev.attributes["manufacturer_name"]= result["manufacturer_name"]
        ev.attributes["oui_prefix"] = result["oui_prefix"]

    return ev