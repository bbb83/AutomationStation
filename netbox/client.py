import requests

#this shit dont work, ignore

class NetBoxClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _get(self, path: str, params: dict | None = None):
        resp = self.session.get(f"{self.base_url}{path}", params=params)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, payload: dict):
        resp = self.session.post(f"{self.base_url}{path}", json=payload)
        resp.raise_for_status()
        return resp.json()

    def _patch(self, path: str, payload: dict):
        resp = self.session.patch(f"{self.base_url}{path}", json=payload)
        resp.raise_for_status()
        return resp.json()

    #lookups
    def get_device_by_name(self, name: str):
        data = self._get("/api/dcim/devices/", {"name": name})
        return data["results"][0] if data["results"] else None

    def search_ip(self, ip: str):
        data = self._get("/api/ipam/ip-addresses/", {"q": ip})
        return data["results"]

    def get_device_by_ip(self, ip: str):
        #looks up IP in netbox then follows its assigned object if possible.
        ip_results = self.search_ip(ip)
        for ip_obj in ip_results:
            assigned = ip_obj.get("assigned_object")
            if not assigned:
                continue
            device = assigned.get("device")
            if device:
                return device
        return None

    def get_interface(self, device_id: int, name: str):
        data = self._get("/api/dcim/interfaces/", {
            "device_id": device_id,
            "name": name,
        })
        return data["results"][0] if data["results"] else None

    def get_site_by_name(self, name: str):
        data = self._get("/api/dcim/sites/", {"name": name})
        return data["results"][0] if data["results"] else None

    def get_role_by_name(self, name: str):
        data = self._get("/api/dcim/device-roles/", {"name": name})
        return data["results"][0] if data["results"] else None

    def get_manufacturer_by_name(self, name: str):
        data = self._get("/api/dcim/manufacturers/", {"name": name})
        return data["results"][0] if data["results"] else None

    def get_device_type_by_model(self, model: str):
        data = self._get("/api/dcim/device-types/", {"model": model})
        return data["results"][0] if data["results"] else None

    #helpers
    def create_site(self, name: str, slug: str):
        return self._post("/api/dcim/sites/", {"name": name, "slug": slug})

    def create_role(self, name: str, slug: str, color: str = "9e9e9e"):
        return self._post("/api/dcim/device-roles/", {
            "name": name,
            "slug": slug,
            "color": color,
        })

    def create_manufacturer(self, name: str, slug: str):
        return self._post("/api/dcim/manufacturers/", {
            "name": name,
            "slug": slug,
        })

    def create_device_type(self, manufacturer_id: int, model: str, slug: str):
        return self._post("/api/dcim/device-types/", {
            "manufacturer": manufacturer_id,
            "model": model,
            "slug": slug,
        })

    def create_device(self, *, name: str, site_id: int, role_id: int, device_type_id: int, status: str = "active"):
        return self._post("/api/dcim/devices/", {
            "name": name,
            "site": site_id,
            "role": role_id,
            "device_type": device_type_id,
            "status": status,
        })

    def create_interface(self, *, device_id: int, name: str, type_value: str = "1000base-t"):
        return self._post("/api/dcim/interfaces/", {
            "device": device_id,
            "name": name,
            "type": type_value,
        })

    def create_ip_address(self, address: str, assigned_object_type: str, assigned_object_id: int, status: str = "active"):
        return self._post("/api/ipam/ip-addresses/", {
            "address": address,
            "status": status,
            "assigned_object_type": assigned_object_type,
            "assigned_object_id": assigned_object_id,
        })

    #to update helpers
    def update_device(self, device_id: int, payload: dict):
        return self._patch(f"/api/dcim/devices/{device_id}/", payload)

    def update_device_custom_fields(self, device_id: int, custom_fields: dict):
        return self.update_device(device_id, {"custom_fields": custom_fields})

    def set_primary_ip4(self, device_id: int, ip_id: int):
        return self.update_device(device_id, {"primary_ip4": ip_id})

    #helpers that check to see if we already have object before creating new one

    def ensure_site(self, name: str, slug: str):
        return self.get_site_by_name(name) or self.create_site(name, slug)

    def ensure_role(self, name: str, slug: str, color: str = "9e9e9e"):
        return self.get_role_by_name(name) or self.create_role(name, slug, color)

    def ensure_manufacturer(self, name: str, slug: str):
        return self.get_manufacturer_by_name(name) or self.create_manufacturer(name, slug)

    def ensure_device_type(self, manufacturer_id: int, model: str, slug: str):
        return self.get_device_type_by_model(model) or self.create_device_type(manufacturer_id, model, slug)