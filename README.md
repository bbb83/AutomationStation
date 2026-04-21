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

    NETBOX_URL=http://your-netbox-url
    NETBOX_TOKEN=your_api_token
    SUBNET=192.168.1.0/24
    CONFIDENCE_THRESHOLD=75
    DATABASE_URL=sqlite:///automation_station.db

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
