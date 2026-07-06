import sys
import time
import csv
import smtplib
import subprocess
from email.mime.text import MIMEText
from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP

# --- NIDS STATE TRACKING ---
port_scan_tracker = {}
SCAN_THRESHOLD = 250  

dos_tracker = {}
DOS_THRESHOLD = 2000  
TIME_WINDOW = 1.0   

brute_force_tracker = {}
BF_THRESHOLD = 20         
BF_TIME_WINDOW = 10.0     
AUTH_PORTS = {21, 22, 23, 3389}

# --- BASELINE TELEMETRY (NEW) ---
BASELINE_FILE = "nids_baseline.csv"
BASELINE_INTERVAL = 10 # Log normal traffic volume every 10 seconds
baseline_packet_count = 0
last_baseline_time = time.time()

# --- LOGGING ENGINE ---
LOG_FILE = "nids_alerts.csv"

# --- EMAIL CONFIGURATION ---
EMAIL_SENDER = "deepanshukumar2118@gmail.com"
EMAIL_PASSWORD = "your_16_character_app_password" 
EMAIL_RECEIVER = "deepanshukumar2118@gmail.com"

def launch_dashboard():
    """Spawns the Streamlit dashboard in a completely detached Windows process."""
    print("[*] Bridging Systems: Spawning independent Dashboard interface...")
    try:
        # Opens a new CMD window and executes streamlit without blocking the sniffer
        subprocess.Popen(["cmd.exe", "/c", "start", "cmd.exe", "/k", "streamlit run nids_dashboard.py"])
    except Exception as e:
        print(f"[!] Bridge Failure: Could not launch dashboard. Error: {e}")

def dispatch_email_alert(src_ip, dst_ip, attack_type, details):
    subject = f"NIDS CRITICAL EVENT: {attack_type} Detected"
    body = f"Automated NIDS Alert:\n\nTarget System Under Attack.\nSource IP: {src_ip}\nDestination IP: {dst_ip}\nAttack Vector: {attack_type}\nTelemetry: {details}\n\nImmediate remediation required."
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls() 
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        print(f"[*] SMTP Engine: Alert successfully dispatched to administrator.")
    except Exception as e:
        print(f"[!] SMTP Failure: Could not dispatch email. Error: {e}")

def log_alert(src_ip, dst_ip, attack_type, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, src_ip, dst_ip, attack_type, details])

def log_baseline():
    """Writes the volume of benign traffic to the baseline ledger."""
    global baseline_packet_count, last_baseline_time
    current_time = time.time()
    
    if current_time - last_baseline_time >= BASELINE_INTERVAL:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(BASELINE_FILE, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([timestamp, baseline_packet_count])
        except Exception:
            pass # Fail silently to prevent sniffer interruption
        
        # Reset counters for the next 10-second window
        baseline_packet_count = 0
        last_baseline_time = current_time

def detect_brute_force(src_ip, dst_ip, dst_port):
    if dst_port not in AUTH_PORTS:
        return 
    current_time = time.time()
    if src_ip not in brute_force_tracker:
        brute_force_tracker[src_ip] = []
    brute_force_tracker[src_ip].append(current_time)
    brute_force_tracker[src_ip] = [t for t in brute_force_tracker[src_ip] if current_time - t <= BF_TIME_WINDOW]
    attempts = len(brute_force_tracker[src_ip])
    
    if attempts > BF_THRESHOLD:
        msg = f"{attempts} sequential attempts on Auth Port {dst_port}."
        print(f"[!!!] SEVERITY HIGH: Brute Force Detected | {src_ip} --> {dst_ip} | {msg}")
        log_alert(src_ip, dst_ip, "Brute Force", msg)
        brute_force_tracker[src_ip].clear()

def detect_port_scan(src_ip, dst_ip, dst_port):
    if src_ip not in port_scan_tracker:
        port_scan_tracker[src_ip] = set()
    port_scan_tracker[src_ip].add(dst_port)
    unique_ports = len(port_scan_tracker[src_ip])
    
    if unique_ports > SCAN_THRESHOLD:
        msg = f"{unique_ports} ports hit."
        print(f"[!!!] SEVERITY HIGH: Port Scan Detected | {src_ip} --> {dst_ip} | {msg}")
        log_alert(src_ip, dst_ip, "Port Scan", msg)
        port_scan_tracker[src_ip].clear()

def detect_dos(src_ip, dst_ip):
    current_time = time.time()
    if src_ip not in dos_tracker:
        dos_tracker[src_ip] = []
    dos_tracker[src_ip].append(current_time)
    dos_tracker[src_ip] = [t for t in dos_tracker[src_ip] if current_time - t <= TIME_WINDOW]
    packet_velocity = len(dos_tracker[src_ip])
    
    if packet_velocity > DOS_THRESHOLD:
        msg = f"Velocity: {packet_velocity} pkts/sec."
        print(f"[!!!] SEVERITY CRITICAL: DoS Flood Detected | {src_ip} --> {dst_ip} | {msg}")
        log_alert(src_ip, dst_ip, "DoS Flood", msg)
        dispatch_email_alert(src_ip, dst_ip, "DoS Flood", msg)
        dos_tracker[src_ip].clear()

def analyze_packet(packet):
    global baseline_packet_count
    baseline_packet_count += 1 # Count every intercepted packet
    log_baseline() # Check if 10 seconds have elapsed

    if packet.haslayer(IP):
        ip_layer = packet[IP]
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
    else:
        return

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    dst_port = None

    detect_dos(src_ip, dst_ip)

    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport
    
    if dst_port:
        detect_port_scan(src_ip, dst_ip, dst_port)
        detect_brute_force(src_ip, dst_ip, dst_port)

def deploy_sniffer():
    # Initialize Threat Ledger
    try:
        with open(LOG_FILE, mode='x', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "Source IP", "Destination IP", "Attack Type", "Details"])
    except FileExistsError:
        pass 
        
    # Initialize Baseline Ledger
    try:
        with open(BASELINE_FILE, mode='x', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "Packet_Count"])
    except FileExistsError:
        pass

    launch_dashboard() # Trigger the Subprocess Bridge

    print("[*] NIDS Active. Multi-Vector Engines Online. Baseline Telemetry Running...")
    try:
        sniff(prn=analyze_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Interception sequence terminated by user.")
        sys.exit(0)

if __name__ == "__main__":
    deploy_sniffer()