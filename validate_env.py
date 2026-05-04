import os
import sys
from dotenv import load_dotenv
load_dotenv()

REQUIRED = [
    "KEA_API_URL", "KEA_API_USERNAME", "KEA_API_PASSWORD", "KEA_COMMAND", "KEA_SERVICE",
    "SNMP_COMMUNITY", "SNMP_VERSION", "SNMP_TARGET_SUBNET",
    "SNMP_OID_HOSTNAME", "SNMP_OID_DESCRIPTION", "SNMP_OID_UPTIME", "SNMP_OID_INTERFACES",
    "DNS_SERVER", "DNS_DOMAIN",
    "NETBOX_URL", "NETBOX_TOKEN",
    "SUBNET", "DHCP_POOL_START", "DHCP_POOL_END",
    "CONFIDENCE_THRESHOLD",
    "DATABASE_URL",
    "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "MAIL_FROM", "MAIL_TO", "MAIL_REPORT_THRESHOLD"
]

def validate_env():
    missing = [key for key in REQUIRED if not os.getenv(key)]
    if missing:
        raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
    print("[config] Environment variables validated.")

if __name__ == "__main__":
    try:
        validate_env()
    except ValueError as e:
        print(e)
        sys.exit(1)
