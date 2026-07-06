
# Advanced Network Intrusion Detection System (NIDS) 🛡️

## Overview
This repository contains a custom-built, dual-process Network Intrusion Detection System (NIDS) designed to intercept, analyze, and visualize network traffic in real-time. Engineered to bypass standard commercial limitations, the architecture utilizes a Python/Scapy backend for raw packet ingestion and a detached Streamlit frontend for live telemetry visualization.

**Author:** Deepanshu Kumar (Mahi Shrivastava)
**Domain:** Cybersecurity / Network Engineering

## System Architecture
The NIDS operates on an asynchronous, dual-ledger architecture to prevent thread-blocking during high-velocity packet ingestion:
* **The Core Engine (`nids_core.py`):** Intercepts raw TCP/UDP packets at the OSI Network and Transport layers.
* **The Subprocess Bridge:** Spawns a detached Streamlit web server to ensure UI rendering does not interrupt the packet sniffer's execution thread.
* **Dual-Ledger Data Pipeline:** Splits telemetry into `nids_alerts.csv` (threat anomalies) and `nids_baseline.csv` (benign traffic volume) for optimized I/O operations.

## Key Threat Detection Vectors
1. **Volumetric Attacks (DoS / DDoS):** 
   * Tracks time-decay packet velocity.
   * **Threshold:** > 2000 pkts/sec. 
   * **Action:** Triggers `SEVERITY CRITICAL`, logs event, and dispatches automated SMTP email alerts.
2. **Vertical Penetration (Brute Force):**
   * Isolates traffic targeting critical Auth Ports (21, 22, 23, 3389).
   * **Threshold:** > 20 sequential connection attempts within a 10-second window.
   * **Action:** Triggers `SEVERITY HIGH` and logs to the threat ledger.
3. **Horizontal Reconnaissance (Port Scanning):**
   * Maps source IPs attempting lateral network traversal.
   * **Threshold:** > 250 unique ports hit by a single origin.
   * **Action:** Triggers `SEVERITY HIGH` and logs to the threat ledger.

## Prerequisites & Dependencies
Ensure your environment meets the following requirements before deployment:
* **Python 3.8+**
* **Npcap / WinPcap:** Required for Scapy to intercept raw packets on Windows environments.

**Python Libraries:**
```bash
pip install scapy streamlit pandas

```

## Installation & Setup

1. Clone the repository:
```bash
git clone [https://github.com/yourusername/NIDS_PROJECT.git](https://github.com/yourusername/NIDS_PROJECT.git)
cd NIDS_PROJECT

```


2. Configure SMTP Credentials:
* Open `nids_core.py`.
* Locate the `--- EMAIL CONFIGURATION ---` block.
* Insert your administrative email and 16-character App Password.
*(Note: Never commit your actual App Password to a public GitHub repository. Use environment variables in production).*



## Execution Protocol

The system utilizes a bridged deployment. You only need to run the core engine; it will automatically launch the dashboard.

1. Open an **Administrative Command Prompt** (Required for packet sniffing).
2. Execute the core script:
```bash
python nids_core.py

```


3. The Streamlit dashboard will automatically launch in your default web browser, rendering live baseline traffic and threat matrices.

## Empirical Testing Methodology

To validate the detection algorithms, use the following commands from an attacker machine or terminal:

**1. Simulate DoS Flood:**

```bash
nmap --min-rate 3000 -Pn <TARGET_IP>

```

*Expected Result: Triggers Critical alert and dispatches SMTP notification.*

**2. Simulate Brute Force (Bypassing Stateful Firewalls):**

```bash
nping --tcp -p 22 -c 25 --rate 5 <TARGET_IP>

```

*Expected Result: Triggers High Severity vertical attack alert on the Streamlit dashboard.*

## Disclaimer

This tool is engineered for educational purposes and internal network auditing. Do not deploy these scanning techniques against networks or infrastructure for which you do not have explicit authorization.

```

### Operational Security Directive

Before you upload these files to GitHub, you must execute one critical security action. 

Open your local `nids_core.py` file and delete your actual Gmail App Password from the `EMAIL_PASSWORD` variable. Replace it with a placeholder like `"INSERT_APP_PASSWORD_HERE"`. 

If you push the file with your active Google credential inside it, automated bots will scrape your password from GitHub within seconds, compromising your email account. Confirm when this sanitization is complete.

```
