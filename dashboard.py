import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import time
import random
import uuid

# Set page config first
st.set_page_config(
    page_title="FinSafe Sentinel AI - Cyber-Transaction Correlation Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Import custom modules
import networkx as nx
from data_generator import generate_encryption_inventory
from stream_simulator import StreamSimulator
from correlation_engine import CorrelationEngine
from fraud_model import correlated_score, raw_score
from quantum_scanner import scan_encryption_inventory, detect_hndl_risk, detect_sequence_threat
from explainability import explain_threat

# Inject custom CSS for premium cybersecurity dark look
st.markdown("""
<style>
    /* Dark Theme Styles */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
        font-family: 'Outfit', 'Inter', sans-serif;
    }
    
    /* Panel Containers */
    div.element-container {
        border-radius: 8px;
    }
    
    /* Custom Headers */
    .app-title {
        font-size: 32px;
        font-weight: 800;
        background: linear-gradient(90deg, #38bdf8, #818cf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 2px;
    }
    .app-subtitle {
        font-size: 14px;
        color: #94a3b8;
        margin-bottom: 25px;
    }
    
    /* KPI Cards */
    .kpi-row {
        display: flex;
        justify-content: space-between;
        gap: 15px;
        margin-bottom: 25px;
    }
    .kpi-card {
        background-color: #111827;
        border: 1px solid #1f2937;
        border-left: 4px solid #3b82f6;
        border-radius: 8px;
        padding: 16px 20px;
        flex: 1;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        transition: transform 0.2s;
    }
    .kpi-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.2);
    }
    .kpi-card.avoided {
        border-left: 4px solid #10b981;
    }
    .kpi-card.alerts {
        border-left: 4px solid #ef4444;
    }
    .kpi-title {
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        color: #94a3b8;
        letter-spacing: 0.05em;
    }
    .kpi-value {
        font-size: 28px;
        font-weight: 700;
        color: #f3f4f6;
        margin-top: 5px;
    }
    
    /* Threat alerts */
    .alert-banner {
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
    }
    .alert-banner-high {
        background-color: rgba(239, 68, 68, 0.1);
        border: 1px solid #ef4444;
        color: #fca5a5;
    }
    .alert-banner-warning {
        background-color: rgba(245, 158, 11, 0.1);
        border: 1px solid #f59e0b;
        color: #fde047;
    }
</style>
""", unsafe_allow_html=True)

# Helper function to format event details
def format_event_details(evt):
    etype = evt.get("event_type")
    if etype == "login":
        success_str = "Success" if evt.get("success") else "FAILED"
        return f"Device: {evt.get('device_id')} | IP: {evt.get('ip_address')} ({evt.get('location')}) | {success_str}"
    elif etype == "transaction":
        beneficiary_str = "New Beneficiary" if evt.get("is_new_beneficiary") else "Existing Beneficiary"
        return f"TXN ID: {evt.get('transaction_id')} | Amount: ${evt.get('amount'):,.2f} | Dest ACC: {evt.get('destination_account')} | {beneficiary_str}"
    elif etype == "sim_swap":
        flagged_str = "Security Alert Triggered" if evt.get("flagged") else "Normal Swap"
        return f"SIM Swap Operation | {flagged_str}"
    elif etype == "data_transfer":
        gb_size = evt.get("bytes_transferred", 0) / (1024 * 1024 * 1024)
        return f"System: {evt.get('system_name')} | Transferred: {gb_size:.2f} GB | Dest IP: {evt.get('destination_ip')}"
    return "No details"

# Process event and run models
def process_new_event(evt):
    # 1. Add to logs history
    st.session_state.events_history.append(evt)
    
    # 2. Update the graph
    st.session_state.correlation_engine.add_event(evt)
    
    # 3. If it's a transaction, score it
    if evt.get("event_type") == "transaction":
        user = evt.get("user")
        score_res = correlated_score(evt, st.session_state.correlation_engine, user)
        
        # Merge transaction details with score details
        scored_txn = {
            "transaction_id": evt["transaction_id"],
            "user": user,
            "amount": evt["amount"],
            "timestamp": evt["timestamp"],
            "is_new_beneficiary": evt["is_new_beneficiary"],
            "raw_score": score_res["raw_score"],
            "correlated_score": score_res["correlated_score"],
            "adjustment_reason": score_res["adjustment_reason"],
            "status": score_res["status"]
        }
        
        # Check false-positive avoidance
        # Threshold for flagging is 0.60
        if score_res["raw_score"] >= 0.60 and score_res["correlated_score"] < 0.60:
            st.session_state.false_positives_avoided += 1
            
        # Check alert count
        if score_res["status"] == "high":
            st.session_state.alerts_count += 1
            
        st.session_state.scored_transactions.append(scored_txn)
        st.session_state.selected_transaction_id = evt["transaction_id"]
        
        # Run proactive sequence check for this user
        seq_res = detect_sequence_threat(st.session_state.events_history, user)
        if seq_res["threat_detected"]:
            st.session_state.sequence_alerts.append({
                "user": user,
                "timestamp": evt["timestamp"],
                "reason": seq_res["reason"],
                "transaction_id": seq_res["transaction_id"],
                "amount": seq_res["amount"]
            })
            
    # 4. If it's a data transfer, check for HNDL risk
    if evt.get("event_type") == "data_transfer":
        hndl_res = detect_hndl_risk([evt], st.session_state.encryption_inventory_data)
        if hndl_res:
            st.session_state.hndl_alerts.extend(hndl_res)

# App Initializer
if "initialized" not in st.session_state:
    st.session_state.simulator = StreamSimulator()
    st.session_state.correlation_engine = CorrelationEngine()
    st.session_state.events_history = []
    st.session_state.scored_transactions = []
    st.session_state.false_positives_avoided = 0
    st.session_state.alerts_count = 0
    st.session_state.hndl_alerts = []
    st.session_state.sequence_alerts = []
    st.session_state.selected_transaction_id = None
    st.session_state.selected_user = "All Users"
    st.session_state.autoplay = False
    
    # Store static inventory
    st.session_state.encryption_inventory_data = scan_encryption_inventory(generate_encryption_inventory())
    
    # Pre-populate with historical events to make the dashboard look populated instantly
    print("[Dashboard] Running startup pre-population...")
    for _ in range(30):
        evt = st.session_state.simulator.get_next_event()
        if evt:
            process_new_event(evt)
            
    # Inject a data transfer exfiltration event to demonstrate HNDL scan triggers on load
    hndl_trigger_event = {
        "event_type": "data_transfer",
        "system_name": "Core Banking Ledger",
        "bytes_transferred": int(5.6 * 1024 * 1024 * 1024), # 5.6 GB
        "destination_ip": "104.244.42.1",
        "timestamp": datetime.now()
    }
    process_new_event(hndl_trigger_event)
    
    st.session_state.initialized = True

# Main Layout
st.markdown('<div class="app-title">🛡️ FinSafe Sentinel AI</div>', unsafe_allow_html=True)
st.markdown('<div class="app-subtitle">Real-Time Cybersecurity Telemetry & Financial Transaction Risk Correlation Engine</div>', unsafe_allow_html=True)

# ----------------- SIDEBAR -----------------
with st.sidebar:
    st.image("https://img.icons8.com/nolan/128/security-shield.png", width=70)
    st.markdown("### Control Center")
    
    # Play / Pause Autoplay
    autoplay = st.checkbox("Autoplay Event Stream", value=st.session_state.autoplay)
    st.session_state.autoplay = autoplay
    
    st.markdown("---")
    st.markdown("### Inject Demo Scenarios")
    st.info("Trigger specific chronological attack sequences to test correlation logic:")
    
    # Demo Scenario Buttons
    if st.button("🟢 Safe Transaction", use_container_width=True):
        # Reset state & focus
        user = random.choice(st.session_state.simulator.users)
        _, events = st.session_state.simulator.inject_scenario("safe_transaction", user)
        for e in events:
            process_new_event(e)
        st.session_state.selected_user = user
        st.toast(f"Normal transaction injected for user {user}.", icon="✅")
        st.rerun()
        
    if st.button("🚨 SIM-Swap Fraud", use_container_width=True):
        user = random.choice(st.session_state.simulator.users)
        _, events = st.session_state.simulator.inject_scenario("attack_chain", user)
        for e in events:
            process_new_event(e)
        st.session_state.selected_user = user
        st.toast(f"Cyber-fraud sequence (SIM Swap -> New Login -> Large Txn) injected for {user}!", icon="🚨")
        st.rerun()
        
    if st.button("🛡️ Large Legitimate Transaction", use_container_width=True):
        user = random.choice(st.session_state.simulator.users)
        _, events = st.session_state.simulator.inject_scenario("legitimate_large", user)
        for e in events:
            process_new_event(e)
        st.session_state.selected_user = user
        st.toast(f"Large legitimate transaction (trusted device) injected for {user}. Score should be discounted!", icon="🛡️")
        st.rerun()
        
    st.markdown("---")
    
    # Manual stream tick
    if st.button("⏭️ Tick Single Event", use_container_width=True):
        evt = st.session_state.simulator.get_next_event()
        if evt:
            process_new_event(evt)
            st.toast(f"Event Ticked: {evt['event_type']}")
            st.rerun()
            
    if st.button("🗑️ Clear Dashboard State", use_container_width=True):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()

# ----------------- SECTION 1: KPI ROW -----------------
total_transactions = len([e for e in st.session_state.events_history if e.get("event_type") == "transaction"])
total_cyber_events = len([e for e in st.session_state.events_history if e.get("event_type") in ["login", "sim_swap", "data_transfer"]])

kpi_html = f"""
<div class="kpi-row">
    <div class="kpi-card">
        <div class="kpi-title">Transactions Processed</div>
        <div class="kpi-value">{total_transactions}</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-title">Cyber Security Events</div>
        <div class="kpi-value">{total_cyber_events}</div>
    </div>
    <div class="kpi-card alerts">
        <div class="kpi-title">High Risk Cyber-Alerts</div>
        <div class="kpi-value">{st.session_state.alerts_count}</div>
    </div>
    <div class="kpi-card avoided">
        <div class="kpi-title">False Positives Avoided</div>
        <div class="kpi-value">🛡️ {st.session_state.false_positives_avoided}</div>
    </div>
</div>
"""
st.markdown(kpi_html, unsafe_allow_html=True)

# ----------------- ALERT BANNERS (Proactive Threats & HNDL) -----------------
if st.session_state.sequence_alerts or st.session_state.hndl_alerts:
    col_al1, col_al2 = st.columns(2)
    
    with col_al1:
        if st.session_state.sequence_alerts:
            st.markdown("##### 🚨 Proactive Attack Chains Blocked (Sequence Detection)")
            for alert in st.session_state.sequence_alerts[-2:]: # Show last 2
                time_str = alert["timestamp"].strftime("%H:%M:%S") if isinstance(alert["timestamp"], datetime) else str(alert["timestamp"])
                st.markdown(f"""
                <div class="alert-banner alert-banner-high">
                    <strong>User: {alert['user']} | Time: {time_str}</strong><br/>
                    {alert['reason']}<br/>
                    <strong>Transaction Target:</strong> ID {alert['transaction_id']} for ${alert['amount']:,.2f}
                </div>
                """, unsafe_allow_html=True)
                
    with col_al2:
        if st.session_state.hndl_alerts:
            st.markdown("##### ⚠️ Harvest-Now-Decrypt-Later (HNDL) Risks Flagged")
            for alert in st.session_state.hndl_alerts[-2:]: # Show last 2
                st.markdown(f"""
                <div class="alert-banner alert-banner-warning">
                    <strong>System: {alert['system_name']} ({alert['algorithm']}) | Threat: HNDL Exfiltration</strong><br/>
                    Transferred {alert['transfer_size_gb']} GB of ciphertext to unfamiliar destination IP <code>{alert['destination']}</code>.
                    Algorithm is quantum-vulnerable; data is subject to retroactive decryption.
                </div>
                """, unsafe_allow_html=True)

st.markdown("---")

# ----------------- SECTION 2 & 3: GRID LAYOUT -----------------
col_graph, col_feed = st.columns([7, 5])

# Graph filter selection
user_list = ["All Users"] + sorted(list(st.session_state.simulator.users))

with col_graph:
    st.subheader("🕸️ Network Entity Correlation Graph")
    
    # Filter selection
    selected_user_graph = st.selectbox(
        "Focus on Entity (Filter Subgraph):",
        options=user_list,
        index=user_list.index(st.session_state.selected_user) if st.session_state.selected_user in user_list else 0
    )
    st.session_state.selected_user = selected_user_graph
    
    # Get suspicious paths for drawing
    susp_nodes = set()
    susp_edges = []
    
    if selected_user_graph != "All Users":
        susp_nodes, susp_edges, _ = st.session_state.correlation_engine.find_suspicious_paths(selected_user_graph)
    else:
        # Aggregate all suspicious paths across all users to display them on the complete graph
        for user in st.session_state.simulator.users:
            sn, se, _ = st.session_state.correlation_engine.find_suspicious_paths(user)
            susp_nodes.update(sn)
            susp_edges.extend(se)
            
    # Drawing function
    def draw_network_graph(graph, suspicious_nodes, suspicious_edges, filtered_user=None):
        if filtered_user and filtered_user != "All Users":
            user_node = f"User: {filtered_user}"
            if graph.has_node(user_node):
                # Subgraph: User node, plus neighbors within 2 steps
                nodes_to_keep = list(nx.single_source_shortest_path_length(graph, user_node, cutoff=2).keys())
                subgraph = graph.subgraph(nodes_to_keep)
            else:
                subgraph = nx.Graph()
        else:
            subgraph = graph
            
        if len(subgraph) == 0:
            fig = go.Figure()
            fig.update_layout(title="No graph data available", template="plotly_dark", paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
            return fig
            
        # Layout
        pos = nx.spring_layout(subgraph, k=0.5, seed=42)
        
        # Edge lines
        normal_edge_x, normal_edge_y = [], []
        susp_edge_x, susp_edge_y = [], []
        
        for u, v in subgraph.edges():
            x0, y0 = pos[u]
            x1, y1 = pos[v]
            # Check if this edge is in the suspicious set (undirected match)
            is_susp = (u, v) in suspicious_edges or (v, u) in suspicious_edges
            
            if is_susp:
                susp_edge_x.extend([x0, x1, None])
                susp_edge_y.extend([y0, y1, None])
            else:
                normal_edge_x.extend([x0, x1, None])
                normal_edge_y.extend([y0, y1, None])
                
        edge_traces = []
        if normal_edge_x:
            edge_traces.append(go.Scatter(
                x=normal_edge_x, y=normal_edge_y,
                line=dict(width=1.0, color="rgba(148, 163, 184, 0.25)"),
                hoverinfo='none',
                mode='lines',
                showlegend=False
            ))
        if susp_edge_x:
            edge_traces.append(go.Scatter(
                x=susp_edge_x, y=susp_edge_y,
                line=dict(width=3.5, color="rgba(239, 68, 68, 0.95)"),
                hoverinfo='none',
                mode='lines',
                name='Suspicious Path'
            ))
            
        # Nodes
        node_x, node_y, node_color, node_text, node_size = [], [], [], [], []
        
        # Types and colors
        type_colors = {
            "User": "#3b82f6",         # Blue
            "Device": "#6b7280",       # Gray
            "IP": "#06b6d4",           # Cyan
            "SIM": "#d946ef",           # Pinkish
            "Transaction": "#10b981",   # Green
            "Account": "#eab308"        # Yellow
        }
        
        for node in subgraph.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
            node_type = subgraph.nodes[node].get("type", "Unknown")
            label = subgraph.nodes[node].get("label", node)
            
            node_text.append(f"<b>Type:</b> {node_type}<br><b>Details:</b> {label}")
            
            if node in suspicious_nodes:
                node_color.append("#ef4444") # Red
                node_size.append(18)
            else:
                node_color.append(type_colors.get(node_type, "#94a3b8"))
                node_size.append(11)
                
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            hovertext=node_text,
            text=[subgraph.nodes[n].get("label", n).split(" ")[0] for n in subgraph.nodes()],
            textposition="top center",
            textfont=dict(size=8, color="#cbd5e1"),
            marker=dict(
                color=node_color,
                size=node_size,
                line=dict(width=1, color="#1e293b")
            ),
            showlegend=False
        )
        
        fig = go.Figure(data=edge_traces + [node_trace],
                     layout=go.Layout(
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=0,l=0,r=0,t=0),
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        template="plotly_dark",
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)'
                     ))
        return fig

    fig_graph = draw_network_graph(st.session_state.correlation_engine.graph, susp_nodes, susp_edges, selected_user_graph)
    st.plotly_chart(fig_graph, use_container_width=True)

with col_feed:
    st.subheader("⚡ Live Ingested Cyber-Telemetry Feed")
    # Feed list
    if st.session_state.events_history:
        # Convert to printable dataframe
        feed_data = []
        for e in reversed(st.session_state.events_history):
            time_str = e["timestamp"].strftime("%H:%M:%S") if isinstance(e["timestamp"], datetime) else str(e["timestamp"])
            feed_data.append({
                "Time": time_str,
                "Event Type": e["event_type"].upper(),
                "User ID": e.get("user", "System"),
                "Telemetry Details": format_event_details(e)
            })
            
        df_feed = pd.DataFrame(feed_data).head(12)
        
        # Color row display using native Streamlit styler
        def color_event_type(val):
            if val == "TRANSACTION":
                return 'color: #10b981; font-weight: bold;'
            elif val == "LOGIN":
                return 'color: #3b82f6;'
            elif val == "SIM_SWAP":
                return 'color: #d946ef; font-weight: bold;'
            elif val == "DATA_TRANSFER":
                return 'color: #f59e0b;'
            return ''
            
        st.dataframe(
            df_feed.style.map(color_event_type, subset=['Event Type']),
            use_container_width=True,
            hide_index=True,
            height=370
        )
    else:
        st.write("No events ingested yet.")

st.markdown("---")

# ----------------- SECTION 4: FRAUD DETECTION & FP ANALYSIS -----------------
st.subheader("🤖 Transaction Anomaly Scoring & Correlation Alignment")
st.markdown("Sort or filter this table by **Raw vs Correlated Delta** to view cases where the correlation engine adjusted false positives.")

if st.session_state.scored_transactions:
    df_txns = pd.DataFrame(st.session_state.scored_transactions)
    df_txns["Delta"] = round(df_txns["raw_score"] - df_txns["correlated_score"], 2)
    
    # Columns display
    display_cols = ["transaction_id", "user", "amount", "raw_score", "correlated_score", "Delta", "status", "adjustment_reason"]
    
    # Filters
    delta_filter = st.checkbox("Show only False-Positives Avoided (Positive Delta)")
    if delta_filter:
        df_display = df_txns[df_txns["Delta"] > 0.1]
    else:
        df_display = df_txns.copy()
        
    df_display = df_display[display_cols].sort_values("Delta", ascending=False)
    
    # Styled table
    def style_status(val):
        if val == "high":
            return 'background-color: rgba(239, 68, 68, 0.2); color: #fca5a5; font-weight: bold;'
        elif val == "medium":
            return 'background-color: rgba(245, 158, 11, 0.2); color: #fde047;'
        elif val == "low":
            return 'background-color: rgba(16, 185, 129, 0.2); color: #a7f3d0;'
        return ''
        
    st.dataframe(
        df_display.style.map(style_status, subset=['status']),
        use_container_width=True,
        hide_index=True,
        height=300
    )
else:
    st.write("No transactions scored yet.")

st.markdown("---")

# ----------------- SECTION 5 & 6 & 7: EXPLAINABILITY, ACTIONS, & QUANTUM -----------------
col_xai, col_quantum = st.columns([7, 5])

with col_xai:
    st.subheader("💡 Explainable Threat Intelligence (SHAP / Fallback)")
    
    if st.session_state.scored_transactions:
        # Dropdown to select a transaction for explanation
        txn_ids = [t["transaction_id"] for t in reversed(st.session_state.scored_transactions)]
        default_index = 0
        if st.session_state.selected_transaction_id in txn_ids:
            default_index = txn_ids.index(st.session_state.selected_transaction_id)
            
        selected_txn_id = st.selectbox("Select Transaction for Analysis:", options=txn_ids, index=default_index)
        
        # Load the selected transaction
        txn_obj = next(t for t in st.session_state.scored_transactions if t["transaction_id"] == selected_txn_id)
        
        # Query rules triggered for this user
        _, _, rules_triggered = st.session_state.correlation_engine.find_suspicious_paths(txn_obj["user"])
        
        # Run explainability engine
        explanation = explain_threat(txn_obj, txn_obj, rules_triggered)
        
        # Render risk score and narrative
        st.markdown(f"**Unified Risk Score:** `{explanation['risk_score']:.2f}` | **Severity:** `{txn_obj['status'].upper()}`")
        
        # Display Narrative
        st.info(explanation["narrative"])
        
        # Horizontal Plotly Bar Chart of Contributions
        contrib_df = pd.DataFrame(explanation["contributing_factors"])
        
        # Plot
        if not contrib_df.empty:
            # Color code based on direction of contribution (Positive = Red/Orange, Negative = Green)
            contrib_df["Color"] = contrib_df["contribution"].apply(lambda x: "#ef4444" if x > 0 else "#10b981")
            
            fig_bar = go.Figure(go.Bar(
                x=contrib_df["contribution"],
                y=contrib_df["factor"],
                orientation='h',
                marker_color=contrib_df["Color"],
                hovertemplate="Factor: %{y}<br>Weight: %{x:.2f}<extra></extra>"
            ))
            
            fig_bar.update_layout(
                margin=dict(l=10, r=10, t=10, b=10),
                height=220,
                xaxis_title="Risk Contribution Magnitude (Positive adds risk, Negative reduces risk)",
                yaxis=dict(autorange="reversed"),
                template="plotly_dark",
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)'
            )
            st.plotly_chart(fig_bar, use_container_width=True)
            
        # ----------------- SECTION 7: ACTIONS -----------------
        st.markdown("##### Recommended Mitigation Actions")
        act_col1, act_col2, act_col3, act_col4 = st.columns(4)
        
        # Status-based actions recommendation
        status = txn_obj["status"]
        
        with act_col1:
            app_btn = st.button("✅ Approve Transaction", type="secondary" if status == "high" else "primary", use_container_width=True)
            if app_btn:
                st.success(f"Transaction {selected_txn_id} APPROVED.")
                
        with act_col2:
            step_btn = st.button("🔑 Step-Up Auth (MFA)", type="primary" if status == "medium" else "secondary", use_container_width=True)
            if step_btn:
                st.warning(f"Step-Up Verification requested for user {txn_obj['user']}.")
                
        with act_col3:
            block_btn = st.button("🚫 Block Transaction", type="primary" if status == "high" else "secondary", use_container_width=True)
            if block_btn:
                st.error(f"Transaction {selected_txn_id} BLOCKED. Funds held.")
                
        with act_col4:
            esc_btn = st.button("⚡ Escalate to SecOps", use_container_width=True)
            if esc_btn:
                st.toast(f"Incident escalated to Security Operations Team. User profile locked.", icon="🚨")
    else:
        st.write("Score transactions first to view explanations.")

with col_quantum:
    st.subheader("⚛️ Quantum Risk & Encryption Monitoring")
    st.markdown("Monitors system algorithms against Shor's and Grover's quantum threat metrics:")
    
    df_inv = st.session_state.encryption_inventory_data
    
    # Styled table for quantum risk
    def style_quantum_risk(val):
        if val == "High":
            return 'background-color: rgba(239, 68, 68, 0.2); color: #fca5a5; font-weight: bold;'
        elif val == "Medium":
            return 'background-color: rgba(245, 158, 11, 0.2); color: #fde047;'
        elif val == "Low":
            return 'background-color: rgba(16, 185, 129, 0.2); color: #a7f3d0;'
        return ''
        
    st.dataframe(
        df_inv.style.map(style_quantum_risk, subset=['quantum_risk']),
        use_container_width=True,
        hide_index=True,
        height=320
    )

# ----------------- AUTOPLAY EVENT TICK LOOP -----------------
if st.session_state.autoplay:
    # Small sleep before ticking next event
    time.sleep(3.0)
    evt = st.session_state.simulator.get_next_event()
    if evt:
        process_new_event(evt)
    st.rerun()
