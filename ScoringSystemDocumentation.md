# 📄 Automation Station Scoring System Documentation

## Overview
This system assigns a confidence score (0–100) to each device based on collected evidence.  
The goal is to estimate how reliable and well-understood each device is within the network.

Each device is evaluated across three categories:

- Existence  
- Identity  
- Classification  

These scores are then combined into a final overall confidence score.

---

## Scoring Structure

Each category produces a score from 0 to 100, based on a set of weighted tests.  
These tests either add or subtract from the score depending on the evidence available.
The final score is calculated as the average:
Overall Score = (Existence + Identity + Classification) / 3


---

# 1. Existence Score

The existence score determines whether a device is actually present and active on the network.

It is based on confirming activity from multiple sources. Each successful check increases confidence.

### Existence Tests

#### SNMP Response (+50)
**Source:** SNMP  
Strongest indicator since it confirms direct communication with the device.

#### Nmap Open Ports (+25)
**Source:** Nmap  
Indicates the device is reachable and running services.

#### DHCP Active Lease (+20)
**Source:** DHCP  
Shows the device is currently assigned an IP address.

#### DNS Resolution (+5)
**Source:** DNS  
Weak signal, but helps support that the device exists.

---

# 2. Identity Score

The identity score evaluates how confidently the system can determine what device it is.

Unlike existence, this score focuses on **consistency across sources** rather than just presence.

### Identity Tests

#### Multi-Source Presence (+10 to +30)
**Source:** Correlation (Nmap, SNMP, DHCP, DNS)  
More sources that detect the same device increases confidence.

#### MAC Address Match (+25)
**Source:** Nmap + DHCP  
Strong indicator when both sources report the same MAC address.

#### MAC Address Observed (+10)
**Source:** Nmap / DHCP  
Basic identifying information used for device tracking.

#### DHCP Presence (+10)
**Source:** DHCP  
Confirms the device is actively managed on the network.

#### Hostname Agreement (+10 to +20)
**Source:** SNMP + DHCP + DNS  
Matching hostnames across multiple sources strengthens identity confidence.

#### Manufacturer Evidence (+10)
**Source:** OUI Lookup / Nmap Vendor  
Provides vendor-level identification of the device.

#### MAC Conflict (−30)
**Source:** Cross-source comparison  
Penalizes when multiple different MAC addresses are associated with the same device.

#### Hostname Conflict (−15)
**Source:** SNMP + DHCP + DNS  
Penalizes inconsistent naming across sources.

---

# 3. Classification Score

The classification score determines how well the system understands the type or role of a device.

It relies on identifying recognizable characteristics such as system identifiers, service profiles, manufacturer information, and naming patterns.

### Classification Tests

#### SNMP System Info (+60)
**Source:** SNMP  
Strongest indicator because it provides detailed device metadata.

#### Nmap Service Profile (+25)
**Source:** Nmap  
Identifies services and helps infer device roles.

#### OUI Manufacturer Lookup (+15)
**Source:** IEEE OUI / MAC Address  
Provides vendor-level classification.

#### DNS Naming Hints (+5)
**Source:** DNS  
Uses hostname patterns to infer device type.

---

# Evidence Correlation

All scoring is based on **correlated evidence** gathered from multiple sources and combined into a unified device record before scoring occurs.

This ensures:
- Each device is evaluated completely  
- Evidence from different sources can reinforce or contradict each other  

---

# Output and Visualization

Scores are applied to each device and stored as:

- Custom fields (numeric scores)
- Tags (pass/fail results for each test)

Tags include weight indicators (e.g., `+30`, `-15`) to improve transparency and show how each test contributed to the final score.

---

# Summary

- **Existence** → Confirms the device is present  
- **Identity** → Confirms the device is consistent across sources  
- **Classification** → Determines what the device is  

Weights are based on how **reliable each data source is**, with penalties applied for conflicting information.
