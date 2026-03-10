import xml.etree.ElementTree as ET

def parse_hosts(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    hosts_out = []

    for h in root.findall("host"):
        status_el = h.find("status")
        status = status_el.get("state") if status_el is not None else "unknown"

        ip = None
        mac = None
        vendor = None
        for a in h.findall("address"):
            at = a.get("addrtype")
            if at == "ipv4":
                ip = a.get("addr")
            elif at == "mac":
                mac = a.get("addr")
                vendor = a.get("vendor")

        hostnames = []
        hn_el = h.find("hostname")
        if hn_el is not None:
            for he in hn_el.findall("hostname"):
                name = he.get("name")
                if name:
                    hostnames.append(name)
        ports_out = []
        ports_el = h.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                proto = p.get("protocol")
                portid = p.get("portid")

                state_el = p.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"

                svc_el = p.find("service")
                service = svc_el.get("name") if svc_el is not None else None
                product = svc_el.get("product") if svc_el is not None else None
                version = svc_el.get("version") if svc_el is not None else None

                ports_out.append({
                    "port": int(portid) if portid and portid.isdigit() else portid,
                    "proto": proto,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version
                })
    
        os_obj = None
        os_el = h.find("os")
        if os_el is not None:
            best_name = None
            best_acc = -1
            for m in os_el.findall("osmatch"):
                acc = m.get("accuracy")
                acc_i = int(acc) if acc and acc.isdigit() else 0
                if acc_i > best_acc:
                    best_acc = acc_i
                    best_name = m.get("name")
            if best_name is not None:
                os_obj = {"name": best_name, "accuracy": best_acc}

        if ip:
            hosts_out.append({
                "ip": ip,
                "status": status,
                "hostnames": hostnames,
                "mac": mac,
                "vendor": vendor,
                "os": os_obj,
                "ports": ports_out
            })       

    return hosts_out
def live_ips_from_discovery(xml_text: str) -> list[str]:
    hosts = parse_hosts(xml_text)
    return [h["ip"] for h in hosts if h.get("status") == "up" and h.get("ip")]
