from models.device_record import DeviceRecord
from models.scoring_result import ScoringResult
from netbox.client import NetBoxClient

#this shit doesnt work ignore

class NetBoxSync:
    def __init__(self, client: NetBoxClient):
        self.client = client

    def determine_confidence_status(self, result: ScoringResult) -> str:
        if result.overall_score >= 80:
            return "High"
        if result.overall_score >= 50:
            return "Medium"
        return "Low"

    def slugify(self, text: str) -> str:
        return (
            text.lower()
            .replace(" ", "-")
            .replace("_", "-")
            .replace("/", "-")
        )

    def choose_device_name(self, device: DeviceRecord) -> str:
        hostname = device.get_primary_hostname()
        if hostname:
            return hostname
        if device.ip:
            return f"discovered-{device.ip.replace('.', '-')}"
        if device.mac:
            return f"discovered-{device.mac.replace(':', '').lower()}"
        return "discovered-unknown"

    def choose_interface_name(self, device: DeviceRecord) -> str:
        return "mgmt0"

    def find_matching_device(self, device: DeviceRecord):
        hostname = device.get_primary_hostname()
        if hostname:
            match = self.client.get_device_by_name(hostname)
            if match:
                return match

        if device.ip:
            match = self.client.get_device_by_ip(device.ip)
            if match:
                return match

        return None

    def ensure_defaults(self):
        site = self.client.ensure_site("AutoDiscovery", "autodiscovery")
        role = self.client.ensure_role("Discovered Device", "discovered-device")

        manufacturer = self.client.ensure_manufacturer("Unknown Vendor", "unknown-vendor")
        device_type = self.client.ensure_device_type(
            manufacturer_id=manufacturer["id"],
            model="Generic Discovered Device",
            slug="generic-discovered-device",
        )

        return site, role, manufacturer, device_type

    def ensure_device_exists(self, device: DeviceRecord):
        existing = self.find_matching_device(device)
        if existing:
            return existing, False

        site, role, _, device_type = self.ensure_defaults()
        name = self.choose_device_name(device)

        created = self.client.create_device(
            name=name,
            site_id=site["id"],
            role_id=role["id"],
            device_type_id=device_type["id"],
            status="active",
        )
        return created, True

    def ensure_interface_and_ip(self, netbox_device: dict, device: DeviceRecord):
        iface_name = self.choose_interface_name(device)

        iface = self.client.get_interface(netbox_device["id"], iface_name)
        if not iface:
            iface = self.client.create_interface(
                device_id=netbox_device["id"],
                name=iface_name,
                type_value="1000base-t",
            )

        if device.ip:
            address = f"{device.ip}/32"
            ip_obj = self.client.create_ip_address(
                address=address,
                assigned_object_type="dcim.interface",
                assigned_object_id=iface["id"],
                status="active",
            )
            self.client.set_primary_ip4(netbox_device["id"], ip_obj["id"])
            return iface, ip_obj

        return iface, None

    def push_result(self, device: DeviceRecord, result: ScoringResult):
        netbox_device, created = self.ensure_device_exists(device)

        iface = None
        ip_obj = None
        try:
            iface, ip_obj = self.ensure_interface_and_ip(netbox_device, device)
        except Exception as e:
            print(f"[WARN] Interface/IP step failed for {netbox_device['name']}: {e}")

        status = self.determine_confidence_status(result)

        custom_fields = {
            "existence_confidence": result.existence_score,
            "identity_confidence": result.identity_score,
            "classification_confidence": result.classification_score,
            "overall_confidence": result.overall_score,
            "confidence_status": status,
            "confidence_details": result.to_dict(),
        }

        updated = self.client.update_device_custom_fields(netbox_device["id"], custom_fields)

        action = "CREATED" if created else "UPDATED"
        print(
            f"[INFO] {action} device={netbox_device['name']} "
            f"ip={device.ip} iface={(iface or {}).get('name')} "
            f"score={result.overall_score}"
        )

        return updated