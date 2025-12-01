import streamlit as st
import pandas as pd
import time
import plotly.express as px
import os

# --- CONFIGURATION ---
st.set_page_config(
    page_title="Agent Hunter SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.title("🛡️ Agent Hunter: Active WAF Monitor")
st.markdown("### 🔴 Live Security Operations Center (SOC)")

# File Config (Must match the file created by waf.py)
LOG_FILE = "waf_logs.csv"

# --- LAYOUT SETUP ---
# Create placeholder containers so we can update them without refreshing the page
kpi_container = st.container()
col1, col2, col3, col4 = kpi_container.columns(4)

st.divider()

# Layout for Charts and Logs
chart_col, log_col = st.columns([2, 1])

with chart_col:
    st.subheader("Real-Time Threat Analysis")
    chart_placeholder = st.empty()

with log_col:
    st.subheader("Event Feed")
    log_placeholder = st.empty()

# --- HELPER FUNCTIONS ---
def get_status_color(action):
    if action == "BLOCK": return "inverse" # Red in Streamlit
    if action == "CHALLENGE": return "off" # Yellow/Orange look
    return "normal" # Green

# --- LIVE MONITORING LOOP ---
if not os.path.exists(LOG_FILE):
    st.warning("⚠️ Waiting for WAF connection... (Please run 'python waf.py')")
    # Loop until file appears
    while not os.path.exists(LOG_FILE):
        time.sleep(1)
    st.rerun()

# If file exists, enter live loop
placeholder = st.empty()

while True:
    try:
        # 1. Read the Log File (Only last 200 rows for speed)
        # We use on_bad_lines='skip' to prevent crashes if WAF is writing at exact same moment
        df = pd.read_csv(LOG_FILE, on_bad_lines='skip')
        
        if len(df) > 0:
            # Ensure timestamp parsing
            # df['Timestamp'] = pd.to_datetime(df['Timestamp'])
            
            recent_df = df.tail(100)
            latest_event = df.iloc[-1]
            
            # 2. Calculate KPIs
            current_rps = latest_event['Rolling_RPS']
            current_variance = latest_event['Packet_Variance']
            total_blocks = len(df[df['Action'] == 'BLOCK'])
            total_challenges = len(df[df['Action'] == 'CHALLENGE'])
            
            # 3. Update KPI Metrics
            with kpi_container:
                col1.metric("Network Velocity", f"{int(current_rps)} RPS", delta_color="inverse")
                col2.metric("Packet Variance", f"{int(current_variance)}", help="High variance indicates Data Exfiltration")
                col3.metric("Total Blocks", f"{total_blocks}", delta=1 if latest_event['Action'] == 'BLOCK' else 0)
                
                # Dynamic Status Indicator
                status_text = "✅ SYSTEM SECURE"
                if latest_event['Action'] == "BLOCK":
                    status_text = "⛔ THREAT BLOCKED"
                    col4.error(status_text)
                elif latest_event['Action'] == "CHALLENGE":
                    status_text = "✋ VERIFYING USER"
                    col4.warning(status_text)
                else:
                    col4.success(status_text)

            # 4. Update Charts
            # We plot RPS vs Threat Score to show the correlation
            fig = px.scatter(
                recent_df, 
                x='Rolling_RPS', 
                y='AI_Probability', 
                color='Action',
                size='Packet_Variance', # Bubbles get bigger with variance
                title="Live Threat Clusters (Size = Variance)",
                color_discrete_map={'BLOCK': 'red', 'CHALLENGE': 'orange', 'ALLOW': 'blue'},
                range_y=[0, 1.1],
                range_x=[0, max(100, recent_df['Rolling_RPS'].max())],
                template="plotly_dark",
                height=400
            )
            chart_placeholder.plotly_chart(fig, use_container_width=True)
            
            # 5. Update Log Table (Most recent on top)
            display_cols = ['Timestamp', 'Source IP Address', 'Rolling_RPS', 'Action']
            log_placeholder.dataframe(
                recent_df[display_cols].sort_index(ascending=False).head(15), 
                use_container_width=True,
                hide_index=True
            )
            
        # Refresh Rate
        time.sleep(0.5)
        
    except Exception as e:
        # If file is empty or locked, just wait a beat
        time.sleep(1)