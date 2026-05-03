# dashboard/app.py
import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

st.set_page_config(
    page_title="SOAR Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

DB_PATH = "logs/incidents.db"

# ── Custom CSS ──
st.markdown("""
<style>
[data-testid="stMetricValue"] { font-size: 2rem; font-weight: 700; }
[data-testid="stMetricDelta"] { font-size: 0.85rem; }
.block-container { padding-top: 1.5rem; }
div[data-testid="metric-container"] {
    background: #f8f9fa; border: 1px solid #e9ecef;
    border-radius: 8px; padding: 1rem;
}
</style>
""", unsafe_allow_html=True)

# ── Load Data ──
@st.cache_data(ttl=5)
def load_incidents():
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT * FROM incidents ORDER BY id DESC", conn)
    conn.close()
    return df

# ── Sidebar ──
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=60)
st.sidebar.title("🛡️ SOAR Platform")
st.sidebar.markdown("---")
page = st.sidebar.radio("Navigate", ["📊 Dashboard", "🚨 Incidents", "🔍 Enrichment", "⚙️ Pipeline"])
st.sidebar.markdown("---")
st.sidebar.markdown(f"**Last Refresh:** {datetime.now().strftime('%H:%M:%S')}")
if st.sidebar.button("🔄 Refresh Data"):
    st.cache_data.clear()
    st.rerun()

df = load_incidents()

# ════════════════════════════════
# PAGE 1 — DASHBOARD
# ════════════════════════════════
if page == "📊 Dashboard":
    st.title("📊 SOC Dashboard")
    st.caption(f"SOAR Incident Response Platform — {datetime.now().strftime('%A, %d %B %Y')}")

    if df.empty:
        st.info("No incidents yet. Run `python main.py` to generate data.")
        st.stop()

    # ── KPI Row ──
    total     = len(df)
    attacks   = len(df[df["severity"].notna()])
    blocked   = len(df[df["is_blocked"] == 1])
    critical  = len(df[df["severity"] == "critical"])

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total Incidents",  total,   f"+{total} logged")
    k2.metric("Attacks Detected", attacks, f"{round(attacks/total*100)}% of traffic")
    k3.metric("IPs Blocked",      blocked, "auto-response")
    k4.metric("Critical Severity",critical,f"{round(critical/total*100)}% critical")

    st.markdown("---")
    col1, col2 = st.columns(2)

    # ── Attack Type Breakdown ──
    with col1:
        st.subheader("Attack Type Breakdown")
        attack_counts = df["prediction"].value_counts().reset_index()
        attack_counts.columns = ["Attack Type", "Count"]
        fig = px.pie(
            attack_counts, names="Attack Type", values="Count",
            color_discrete_sequence=px.colors.sequential.RdBu,
            hole=0.4
        )
        fig.update_layout(margin=dict(t=20, b=20), height=300)
        st.plotly_chart(fig, use_container_width=True)

    # ── Severity Distribution ──
    with col2:
        st.subheader("Severity Distribution")
        sev_order = ["critical", "high", "medium", "low"]
        sev_counts = df["severity"].fillna("normal").value_counts()
        sev_df = pd.DataFrame({
            "Severity": sev_counts.index,
            "Count": sev_counts.values
        })
        color_map = {
            "critical": "#dc3545", "high": "#fd7e14",
            "medium": "#ffc107",   "low": "#28a745", "normal": "#6c757d"
        }
        fig2 = px.bar(
            sev_df, x="Severity", y="Count",
            color="Severity", color_discrete_map=color_map,
            text="Count"
        )
        fig2.update_layout(
            showlegend=False, margin=dict(t=20, b=20),
            height=300, plot_bgcolor="rgba(0,0,0,0)"
        )
        fig2.update_traces(textposition="outside")
        st.plotly_chart(fig2, use_container_width=True)

    # ── Top IPs ──
    st.subheader("Top Source IPs")
    top_ips = df.groupby("ip").agg(
        Incidents=("id","count"),
        Avg_Abuse_Score=("abuse_score","mean"),
        Blocked=("is_blocked","sum")
    ).sort_values("Incidents", ascending=False).head(10).reset_index()
    top_ips.columns = ["IP", "Incidents", "Avg Abuse Score", "Times Blocked"]
    top_ips["Avg Abuse Score"] = top_ips["Avg Abuse Score"].round(1)
    st.dataframe(top_ips, use_container_width=True, hide_index=True)

# ════════════════════════════════
# PAGE 2 — INCIDENTS
# ════════════════════════════════
elif page == "🚨 Incidents":
    st.title("🚨 Incident Log")

    if df.empty:
        st.info("No incidents yet.")
        st.stop()

    # Filters
    fc1, fc2, fc3 = st.columns(3)
    sev_filter  = fc1.multiselect("Severity", df["severity"].dropna().unique().tolist(), default=df["severity"].dropna().unique().tolist())
    atk_filter  = fc2.multiselect("Attack Type", df["prediction"].unique().tolist(), default=df["prediction"].unique().tolist())
    blk_filter  = fc3.selectbox("Blocked", ["All", "Blocked Only", "Not Blocked"])

    filtered = df[
        df["severity"].isin(sev_filter) &
        df["prediction"].isin(atk_filter)
    ]
    if blk_filter == "Blocked Only":
        filtered = filtered[filtered["is_blocked"] == 1]
    elif blk_filter == "Not Blocked":
        filtered = filtered[filtered["is_blocked"] == 0]

    st.markdown(f"Showing **{len(filtered)}** of {len(df)} incidents")

    # Display table
    display_cols = ["id", "timestamp", "ip", "prediction", "severity",
                    "confidence", "vt_ratio", "abuse_score",
                    "country", "is_blocked"]
    st.dataframe(
        filtered[display_cols].rename(columns={
            "id": "ID", "timestamp": "Time", "ip": "Source IP",
            "prediction": "Attack", "severity": "Severity",
            "confidence": "Confidence", "vt_ratio": "VT Ratio",
            "abuse_score": "Abuse Score", "country": "Country",
            "is_blocked": "Blocked"
        }),
        use_container_width=True, hide_index=True
    )

    # Export
    csv = filtered.to_csv(index=False)
    st.download_button(
        "⬇️ Export CSV", csv,
        file_name=f"soar_incidents_{datetime.now().strftime('%Y%m%d')}.csv",
        mime="text/csv"
    )

# ════════════════════════════════
# PAGE 3 — ENRICHMENT
# ════════════════════════════════
elif page == "🔍 Enrichment":
    st.title("🔍 IP Enrichment Details")

    if df.empty:
        st.info("No incidents yet.")
        st.stop()

    # Abuse score scatter
    st.subheader("Abuse Score vs VT Detections")
    enrich_df = df[df["vt_ratio"].notna()].copy()
    enrich_df["vt_malicious"] = enrich_df["vt_ratio"].str.split("/").str[0].astype(float, errors="ignore")

    fig3 = px.scatter(
        enrich_df, x="abuse_score", y="vt_malicious",
        color="severity", hover_data=["ip", "prediction", "country"],
        color_discrete_map={"critical":"#dc3545","high":"#fd7e14","medium":"#ffc107","low":"#28a745"},
        labels={"abuse_score": "AbuseIPDB Score", "vt_malicious": "VT Malicious Engines"},
        size_max=15
    )
    fig3.update_layout(height=400, plot_bgcolor="rgba(0,0,0,0)")
    fig3.add_vline(x=80, line_dash="dash", line_color="red", annotation_text="Auto-block threshold")
    st.plotly_chart(fig3, use_container_width=True)

    # IP enrichment table
    st.subheader("Per-IP Threat Summary")
    ip_summary = df.groupby("ip").agg(
        Country=("country", "first"),
        ASN=("asn", "first"),
        Max_Abuse=("abuse_score", "max"),
        VT_Ratio=("vt_ratio", "first"),
        Incidents=("id", "count"),
        Blocked=("is_blocked", "max")
    ).reset_index()
    ip_summary.columns = ["IP", "Country", "ASN", "Max Abuse Score", "VT Ratio", "Incidents", "Blocked"]
    st.dataframe(ip_summary, use_container_width=True, hide_index=True)

# ════════════════════════════════
# PAGE 4 — PIPELINE
# ════════════════════════════════
elif page == "⚙️ Pipeline":
    st.title("⚙️ Pipeline Status")

    # Architecture diagram
    st.subheader("Automated Response Pipeline")
    p1, p2, p3 = st.columns([1, 0.15, 1])

    with p1:
        st.markdown("""
        <div style='background:#e8f4fd;border:1px solid #90cdf4;border-radius:8px;padding:1rem;text-align:center;'>
            <div style='font-size:2rem'>🤖</div>
            <div style='font-weight:700;margin:0.5rem 0;'>1. DETECT</div>
            <div style='font-size:0.8rem;color:#555;'>Random Forest Classifier<br>NSL-KDD Features (41)<br>5-class multiclass</div>
            <div style='margin-top:0.5rem;background:#2196F3;color:white;border-radius:4px;padding:2px 8px;font-size:0.75rem;display:inline-block;'>LIVE</div>
        </div>
        """, unsafe_allow_html=True)

    p2.markdown("<div style='text-align:center;font-size:2rem;margin-top:2rem;'>→</div>", unsafe_allow_html=True)

    col_mid, arrow2, col_right = st.columns([1, 0.15, 1])
    with col_mid:
        st.markdown("""
        <div style='background:#fff8e1;border:1px solid #ffd54f;border-radius:8px;padding:1rem;text-align:center;'>
            <div style='font-size:2rem'>🔍</div>
            <div style='font-weight:700;margin:0.5rem 0;'>2. ENRICH</div>
            <div style='font-size:0.8rem;color:#555;'>VirusTotal API<br>AbuseIPDB API<br>GeoIP + ASN lookup</div>
            <div style='margin-top:0.5rem;background:#FF9800;color:white;border-radius:4px;padding:2px 8px;font-size:0.75rem;display:inline-block;'>ACTIVE</div>
        </div>
        """, unsafe_allow_html=True)

    arrow2.markdown("<div style='text-align:center;font-size:2rem;margin-top:2rem;'>→</div>", unsafe_allow_html=True)

    with col_right:
        st.markdown("""
        <div style='background:#f0fff4;border:1px solid #9ae6b4;border-radius:8px;padding:1rem;text-align:center;'>
            <div style='font-size:2rem'>🛡️</div>
            <div style='font-weight:700;margin:0.5rem 0;'>3. RESPOND</div>
            <div style='font-size:0.8rem;color:#555;'>Windows Firewall / iptables<br>Slack Webhook<br>SQLite incident log</div>
            <div style='margin-top:0.5rem;background:#4CAF50;color:white;border-radius:4px;padding:2px 8px;font-size:0.75rem;display:inline-block;'>AUTOMATED</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Stats
    if not df.empty:
        st.subheader("Pipeline Statistics")
        s1, s2, s3, s4 = st.columns(4)
        s1.metric("Total Processed", len(df))
        s2.metric("Attack Rate", f"{round(df['severity'].notna().sum()/len(df)*100)}%")
        s3.metric("Auto-blocked", df["is_blocked"].sum())
        s4.metric("Avg Abuse Score", round(df["abuse_score"].mean(), 1))

    # Config table
    st.subheader("Current Configuration")
    config_data = {
        "Setting": ["VT Malicious Threshold", "AbuseIPDB Auto-block", "Platform", "DB Path", "Poll Interval"],
        "Value":   ["≥ 10 engines", "Score ≥ 80", "Windows (netsh)", "logs/incidents.db", "5 seconds"]
    }
    st.table(pd.DataFrame(config_data))