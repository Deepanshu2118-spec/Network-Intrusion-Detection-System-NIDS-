import streamlit as st
import pandas as pd
import time

# --- SYSTEM CONFIGURATION ---
st.set_page_config(page_title="NIDS Dashboard", layout="wide", page_icon="🛡️")
ALERTS_FILE = "nids_alerts.csv"
BASELINE_FILE = "nids_baseline.csv"

# --- UI HEADER ---
st.title("🛡️ Advanced Network Intrusion Detection System")
st.markdown("### Real-Time Threat Telemetry & Traffic Analysis")
st.divider()

# --- DATA INGESTION ENGINE ---
@st.cache_data(ttl=2)
def load_data():
    # Parse Threat Ledger
    try:
        alerts_df = pd.read_csv(ALERTS_FILE, names=["Timestamp", "Source IP", "Destination IP", "Attack Type", "Details"], header=0)
    except Exception:
        alerts_df = pd.DataFrame(columns=["Timestamp", "Source IP", "Destination IP", "Attack Type", "Details"])
    
    # Parse Baseline Telemetry
    try:
        baseline_df = pd.read_csv(BASELINE_FILE, names=["Timestamp", "Packet_Count"], header=0)
        baseline_df['Timestamp'] = pd.to_datetime(baseline_df['Timestamp'])
    except Exception:
        baseline_df = pd.DataFrame(columns=["Timestamp", "Packet_Count"])
        
    return alerts_df, baseline_df

alerts_df, baseline_df = load_data()

# --- VISUALIZATION: NORMAL VS ANOMALOUS ---
st.subheader("📊 Network Traffic Analysis (Normal vs. Anomalous)")

if not baseline_df.empty:
    st.markdown("**Baseline Traffic Volume (Packets / 10s Window)**")
    # Time-series rendering of benign traffic
    st.line_chart(baseline_df.set_index('Timestamp')['Packet_Count'], color="#00ff00")
else:
    st.info("Awaiting baseline telemetry. Generating normal traffic profile...")

st.divider()

# --- THREAT DISTRIBUTION MATRIX ---
col1, col2 = st.columns(2)

with col1:
    st.subheader("🚨 Threat Distribution Matrix")
    if not alerts_df.empty:
        threat_counts = alerts_df['Attack Type'].value_counts()
        st.bar_chart(threat_counts, color="#ff4b4b")
    else:
        st.success("No critical threats detected. Network is secure.")

with col2:
    st.subheader("🛑 Top Attack Origins")
    if not alerts_df.empty:
        attacker_counts = alerts_df['Source IP'].value_counts().head(5)
        st.bar_chart(attacker_counts, color="#ffa500")
    else:
        st.write("Insufficient data.")

# --- RAW TELEMETRY FEED ---
st.divider()
st.subheader("🗄️ Raw Security Ledger")
if not alerts_df.empty:
    # Display the most recent 15 anomalies
    st.dataframe(alerts_df.tail(15), use_container_width=True) 
else:
    st.write("Ledger empty.")

# --- AUTO-REFRESH PROTOCOL ---
time.sleep(2)
st.rerun()