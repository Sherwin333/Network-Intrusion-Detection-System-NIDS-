import streamlit as st
import subprocess
import os
import signal
import time
from pathlib import Path

st.set_page_config(page_title="NIDS Frontend", layout="wide")

st.title("🚨 Network Intrusion Detection Frontend")

# Session State to track processes
if "processes" not in st.session_state:
    st.session_state.processes = {}

# Helper to start a script
def start_script(name, path):
    if name in st.session_state.processes:
        st.warning(f"{name} is already running.")
    else:
        proc = subprocess.Popen(
            ["python", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            universal_newlines=True,
        )
        st.session_state.processes[name] = proc
        st.success(f"✅ Started {name}")

# Helper to stop a script
def stop_script(name):
    proc = st.session_state.processes.get(name)
    if proc:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        st.success(f"🛑 Stopped {name}")
        del st.session_state.processes[name]
    else:
        st.info(f"{name} is not running.")

# Start/Stop buttons
col1, col2, col3 = st.columns(3)

with col1:
    if st.button("▶️ Start honeypot_listener.py"):
        start_script("honeypot_listener", "honeypot_listener.py")

    if st.button("⏹ Stop honeypot_listener.py"):
        stop_script("honeypot_listener")

with col2:
    if st.button("▶️ Start ha.py"):
        start_script("ha", "ha.py")

    if st.button("⏹ Stop ha.py"):
        stop_script("ha")

with col3:
    if st.button("▶️ Start live_detection.py"):
        start_script("live_detection", "live_detection.py")

    if st.button("⏹ Stop live_detection.py"):
        stop_script("live_detection")

st.divider()

# Display logs
st.subheader("🪵 Live Logs")

for name, proc in st.session_state.processes.items():
    st.write(f"### {name}.py logs")

    if proc.stdout:
        lines = []
        try:
            for _ in range(10):
                line = proc.stdout.readline()
                if not line:
                    break
                # Remove trailing newlines and encode issues
                line = line.strip()
                if line:
                    lines.append(line)
        except Exception as e:
            lines.append(f"[Error reading logs] {str(e)}")

        if lines:
            st.code("\n".join(lines), language="bash")
        else:
            st.write("_No new output..._")
    else:
        st.write("_No output stream._")

# Refresh every 5 sec
st.query_params["dummy"] = str(time.time())
st.write("⏳ App auto-refreshes every few seconds to fetch new logs.")
st.markdown(
    """
    <meta http-equiv="refresh" content="20">
    """,
    unsafe_allow_html=True,
)
