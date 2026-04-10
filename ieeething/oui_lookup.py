# takes oui(first 24 bits) from mac address and compares to ieee database to give manufacturer

import csv
from pathlib import Path
from models.evidence import EvidenceRecord


class OUILookup:
    def __init__(self, oui_file: str):
        self.oui_map: dict[str, str] = {}
        self.load_file(oui_file)

    def load_file(self, oui_file: str) -> None:
        path = Path(oui_file)

        if not path.exists():
            raise FileNotFoundError(f"Couldn't find OUI file: {oui_file}")

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()

                if "(base 16)" in line:
                    parts = line.split("(base 16)")
                    if len(parts) != 2:
                        continue

                    prefix = parts[0].strip().upper()
                    manufacturer = parts[1].strip()

                    if prefix and manufacturer:
                        self.oui_map[prefix] = manufacturer

    def normalize_mac(self, mac: str) -> str:
        return mac.upper().replace("-", "").replace(":", "").replace(".", "")

    def lookup(self, mac: str) -> dict | None:
        if not mac:
            return None

        normalized = self.normalize_mac(mac)
        prefix = normalized[:6]
        manufacturer = self.oui_map.get(prefix)

        if manufacturer:
            return {
                "manufacturer_name": manufacturer,
                "oui_prefix": prefix,
            }

        return None

    def add_to_evidence(self, ev: EvidenceRecord) -> EvidenceRecord:
        if not ev.mac:
            return ev

        result = self.lookup(ev.mac)

        if result:
            ev.manufacturer = result["manufacturer_name"]
            ev.attributes["manufacturer_name"] = result["manufacturer_name"]
            ev.attributes["oui_prefix"] = result["oui_prefix"]

        return ev