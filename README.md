# Automation Station

Automated Network Discovery and NetBox Integration with Confidence-Based
Validation

------------------------------------------------------------------------

## Overview

Automation Station is an automated network discovery and validation
system designed to enhance NetBox by adding intelligent,
confidence-based device auto-discovery.

The system combines multiple discovery methods, logs all scan evidence
into a structured database, applies a weighted confidence scoring model,
and synchronizes all discovered devices into NetBox with validation
transparency.

------------------------------------------------------------------------

## Core Features

### Multi-Method Device Discovery

-   Nmap active scanning
-   SNMP queries
-   DNS/DHCP correlation

### Centralized Database Logging

-   Persistent scan history
-   Time-based validation
-   Conflict detection
-   Re-scoring without re-scanning
-   Full audit trail of scoring decisions

### Confidence-Based Scoring

-   Weighted scoring model
-   Configurable confidence threshold
-   Transparent validation logic
-   False positive reduction

### Automated NetBox Integration

-   Device creation via API
-   IP address assignment
-   Duplicate detection
-   Update handling
-   Validation status tagging

------------------------------------------------------------------------

## System Architecture

1.  Discovery Layer\
    Devices are scanned using Nmap and enriched with SNMP and DNS/DHCP
    data.

2.  Database Logging Layer\
    All raw discovery evidence is stored in a centralized database.

3.  Correlation & Validation\
    Data is normalized and matched by IP, MAC address, and hostname.

4.  Confidence Scoring\
    A weighted scoring engine evaluates validation strength.

5.  NetBox Synchronization\
    All discovered devices are created in NetBox with validation
    metadata.

------------------------------------------------------------------------

## Decision Logic

All discovered devices are added to NetBox.

The confidence score determines device validation status, not whether
the device is created.

-   Score ≥ Threshold → Device marked as **Validated**
-   Score \< Threshold → Device marked as **Unverified** and flagged
    with validation details

Devices below the confidence threshold will:

-   Still be created in NetBox
-   Include confidence score metadata
-   Include flags showing which validation checks passed or failed
-   Be marked for administrative review

This ensures full inventory visibility while maintaining transparency
about device reliability.

------------------------------------------------------------------------

## Database Architecture

### Devices Table

-   device_id (Primary Key)
-   ip_address
-   mac_address
-   hostname
-   first_seen
-   last_seen
-   current_confidence_score
-   classification_status

### Scan_Results Table

-   scan_id (Primary Key)
-   device_id (Foreign Key)
-   source (nmap / snmp / dns / dhcp)
-   raw_data (JSON)
-   timestamp

### Confidence_History Table

-   device_id
-   score
-   timestamp
-   decision (validated / unverified)

------------------------------------------------------------------------

## Technologies Used

-   Python
-   python-nmap
-   pysnmp
-   pynetbox
-   NetBox REST API
-   SQLite or PostgreSQL
-   SQLAlchemy
-   Docker

------------------------------------------------------------------------

## Installation

### Clone Repository

``` bash
git clone https://github.com/your-org/automation-station.git
cd automation-station
```

### Install Dependencies

``` bash
pip install -r requirements.txt
```

### Configure Environment Variables (.env)

    # ─── Kea DHCP REST API ─────────────────
    KEA_API_URL=http:/your-kea-url:port
    KEA_API_USERNAME=your-kea-username
    KEA_API_PASSWORD=your-kea-password
    KEA_COMMAND=lease4-get-all
    KEA_SERVICE=dhcp4

    # ─── SNMP ──────────────────────────────
    SNMP_COMMUNITY=your_community_name
    SNMP_VERSION=2c # 2c or v1
    SNMP_TARGET_SUBNET=192.168.1.0/24

    # SNMP OIDs
    SNMP_OID_HOSTNAME=1.3.6.1.2.1.1.5.0
    SNMP_OID_DESCRIPTION=1.3.6.1.2.1.1.1.0
    SNMP_OID_UPTIME=1.3.6.1.2.1.1.3.0
    SNMP_OID_INTERFACES=1.3.6.1.2.1.2.2.1.2

    # ─── DNS ───────────────────────────────
    DNS_SERVER=192.168.1.0
    DNS_DOMAIN=your.domain

    # ─── NetBox ────────────────────────────
    NETBOX_URL=http://your-netbox-url
    NETBOX_TOKEN=your-netbox-token

    # ─── Network ───────────────────────────
    SUBNET=192.168.1.0/24
    DHCP_POOL_START=192.168.1.1
    DHCP_POOL_END=192.168.1.254

    # ─── Confidence Scoring ────────────────
    CONFIDENCE_THRESHOLD=75

    # ─── Database ───────────────────────────
    DATABASE_URL=sqlite:///automation_station.db

    # ─── SMTP ───────────────────────────────
    SMTP_HOST=your.smtp.server
    SMTP_PORT=587
    SMTP_USER=smtp-service-username/key
    SMTP_PASS=smtp-service-password/token
    MAIL_FROM=sender.email@domain
    MAIL_TO=receiever.email.1@domain, receiever.email.2@domain
    MAIL_REPORT_THRESHOLD=40

### Initialize Database

``` bash
python init_db.py
```

### Run Application

``` bash
python main.py
```

------------------------------------------------------------------------

## Evaluation Metrics

-   Detection accuracy
-   False positive rate
-   False negative rate
-   Classification accuracy
-   Confidence score stability
-   API synchronization reliability

------------------------------------------------------------------------

## Intended Users

-   Network Engineers
-   IT Operations Teams
-   SOC Analysts
-   Cybersecurity Teams

------------------------------------------------------------------------

## License

Intended for academic and research use.
