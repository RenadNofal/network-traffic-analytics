"""
Network Traffic Analytics dashboard.
Runs as a Streamlit in Snowflake app and reads from the ANALYTICS views.
"""
import os

import streamlit as st

conn = st.connection("snowflake", ttl=os.getenv("SNOWFLAKE_CONNECTION_TTL"))
session = conn.session()


def q(sql):
    """Run a SQL query and return the result as a pandas DataFrame."""
    return session.sql(sql).to_pandas()


st.title("🌐 Network Traffic Analytics")
st.caption("One week of network flow logs from a small office · Snowflake + Streamlit")

# ---------- KPI cards ----------
kpi = q("""
    SELECT COUNT(*)                                                    AS CONNECTIONS,
           ROUND(SUM(bytes_sent + bytes_received) / POWER(1024, 3), 2) AS TOTAL_GB,
           SUM(IFF(action = 'DENY', 1, 0))                             AS DENIED,
           COUNT(DISTINCT device_name)                                 AS DEVICES
    FROM NETWORK_ANALYTICS.RAW.TRAFFIC_LOGS
""")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Connections", f"{int(kpi.CONNECTIONS[0]):,}")
c2.metric("Total data", f"{kpi.TOTAL_GB[0]} GB")
c3.metric("Denied", f"{int(kpi.DENIED[0]):,}")
c4.metric("Devices", int(kpi.DEVICES[0]))

# ---------- Security alerts ----------
st.subheader("🚨 Security alerts")
alerts = q("SELECT * FROM NETWORK_ANALYTICS.ANALYTICS.V_PORT_SCAN_ALERTS")
if len(alerts) > 0:
    st.error(f"{len(alerts)} possible port scan(s) detected")
    st.dataframe(alerts, use_container_width=True)
else:
    st.success("No port scans detected")

# ---------- Traffic over time ----------
st.subheader("📈 Traffic over the week (connections per hour)")
hourly = q("SELECT hour, connections FROM NETWORK_ANALYTICS.ANALYTICS.V_HOURLY_TRAFFIC ORDER BY hour")
st.line_chart(hourly, x="HOUR", y="CONNECTIONS")

# ---------- Top talkers + services ----------
left, right = st.columns(2)

with left:
    st.subheader("💻 Top 10 talkers (MB)")
    talkers = q("""
        SELECT device_name, total_mb
        FROM NETWORK_ANALYTICS.ANALYTICS.V_TOP_TALKERS
        ORDER BY total_mb DESC LIMIT 10
    """)
    st.bar_chart(talkers, x="DEVICE_NAME", y="TOTAL_MB")

with right:
    st.subheader("🔌 Connections by service")
    services = q("""
        SELECT service, connections
        FROM NETWORK_ANALYTICS.ANALYTICS.V_SERVICE_BREAKDOWN
        ORDER BY connections DESC
    """)
    st.bar_chart(services, x="SERVICE", y="CONNECTIONS")
