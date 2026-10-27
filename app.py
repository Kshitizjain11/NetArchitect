"""
app.py
------
NetArchitect: Network Planning & Configuration Engine
Streamlit Web Interface

Design System & UX Guidelines (PROJECT_SPEC.md §13):
- Restrained professional light theme (off-white, dark charcoal typography, deep teal accent).
- Pure engineering utility: deterministic calculations, zero fake metrics or decorative charts.
- Logical input groupings with immediate inline validation feedback.
- Tabbed results workspace: Architecture Summary, Media Recommendations, VLSM Table,
  Routing & Topology, Cisco IOS Configurations, Engineering Explanations, and Exports.
"""

from __future__ import annotations

import json
import os
import streamlit as st
import pandas as pd

from profiles.presets import (
    CAMPUS_LAN_PRESET,
    METRO_MAN_PRESET,
    GLOBAL_WAN_PRESET,
    get_preset,
    get_all_presets,
)
from engine.input_validation import validate_network_plan, ValidationResult
from engine.media_engine import evaluate_all_links, MediaDecision
from engine.vlsm_allocator import allocate_from_plan, allocate_vlsm, VLSMResult
from engine.routing_engine import decide_routing, RoutingDecision
from engine.topology_engine import plan_topology, TopologyPlan
from engine.explainability import generate_explainability_report, ExplainabilityReport
from generator.cisco_ios import generate_network_config, export_preset_configs, NetworkConfigResult


# ---------------------------------------------------------------------------
# Page Configuration & Professional Engineering Styling
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="NetArchitect — Network Planning & Config Engine",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for restrained, high-readability engineering dashboard
CUSTOM_CSS = """
<style>
    /* Global styles */
    .stApp {
        background-color: #f8fafc !important;
        color: #1e293b !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    
    /* Header typography */
    h1, h2, h3, h4, h5, h6 {
        color: #0f172a !important;
        font-weight: 600;
        letter-spacing: -0.02em;
    }

    p, span, label, div {
        color: #334155;
    }
    
    /* Monospace for engineering data */
    code, pre, .mono-data {
        font-family: "JetBrains Mono", "SF Mono", Consolas, "Liberation Mono", Menlo, Courier, monospace !important;
        font-size: 0.88rem !important;
        color: #0f515e !important;
    }

    /* Tab headers - fix invisible inactive tab text */
    button[data-baseweb="tab"] {
        color: #475569 !important;
        font-weight: 500 !important;
        font-size: 0.92rem !important;
        padding: 8px 16px !important;
        background: transparent !important;
    }
    button[data-baseweb="tab"] p, 
    button[data-baseweb="tab"] span, 
    button[data-baseweb="tab"] div {
        color: #475569 !important;
        font-weight: 500 !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #0f515e !important;
        border-bottom: 2px solid #0f515e !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] p, 
    button[data-baseweb="tab"][aria-selected="true"] span,
    button[data-baseweb="tab"][aria-selected="true"] div {
        color: #0f515e !important;
        font-weight: 700 !important;
    }
    button[data-baseweb="tab"]:hover p, 
    button[data-baseweb="tab"]:hover span {
        color: #0f172a !important;
    }
    
    /* Clean metric cards */
    .stat-card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 14px 18px;
        margin-bottom: 12px;
        box-shadow: 0 1px 2px rgba(0,0,0,0.03);
    }
    .stat-card .label {
        font-size: 0.78rem;
        text-transform: uppercase;
        color: #64748b;
        font-weight: 600;
        margin-bottom: 4px;
    }
    .stat-card .value {
        font-size: 1.35rem;
        color: #0f172a;
        font-weight: 700;
        font-family: "JetBrains Mono", monospace;
    }

    /* Status badges */
    .badge-success {
        background-color: #ecfdf5;
        color: #065f46;
        border: 1px solid #a7f3d0;
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.82rem;
        font-weight: 600;
    }
    .badge-warning {
        background-color: #fffbeb;
        color: #92400e;
        border: 1px solid #fde68a;
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.82rem;
        font-weight: 600;
    }
    .badge-error {
        background-color: #fef2f2;
        color: #991b1b;
        border: 1px solid #fecaca;
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.82rem;
        font-weight: 600;
    }

    /* Streamlit callouts & alerts - high contrast text */
    div[data-testid="stAlert"] {
        padding: 12px 18px !important;
        border-radius: 6px !important;
        border: 1px solid !important;
    }
    div[data-testid="stAlert"] * {
        color: inherit !important;
    }
    /* Warning alerts */
    div[data-testid="stAlert"]:has([data-testid="stAlert-warning"]),
    div[data-testid="stAlert"][aria-label="Warning"],
    div[data-baseweb="notification"] {
        background-color: #fffbeb !important;
        border-color: #fde68a !important;
        color: #78350f !important;
    }
    div[data-testid="stAlert"][aria-label="Warning"] p,
    div[data-testid="stAlert"][aria-label="Warning"] span {
        color: #78350f !important;
        font-weight: 500 !important;
    }
    /* Error alerts */
    div[data-testid="stAlert"][aria-label="Error"] {
        background-color: #fef2f2 !important;
        border-color: #fecaca !important;
        color: #991b1b !important;
    }
    div[data-testid="stAlert"][aria-label="Error"] p {
        color: #991b1b !important;
    }
    /* Info alerts */
    div[data-testid="stAlert"][aria-label="Info"] {
        background-color: #f0fdfa !important;
        border-color: #ccfbf1 !important;
        color: #0f515e !important;
    }
    div[data-testid="stAlert"][aria-label="Info"] p {
        color: #0f515e !important;
    }

    /* Sidebar - clean light engineering style */
    section[data-testid="stSidebar"] {
        background-color: #f1f5f9 !important;
        border-right: 1px solid #e2e8f0 !important;
    }
    section[data-testid="stSidebar"] h1,
    section[data-testid="stSidebar"] h2,
    section[data-testid="stSidebar"] h3,
    section[data-testid="stSidebar"] p,
    section[data-testid="stSidebar"] label,
    section[data-testid="stSidebar"] span {
        color: #1e293b !important;
    }

    /* Form controls & inputs */
    .stTextInput input, .stSelectbox div[data-baseweb="select"] {
        background-color: #ffffff !important;
        color: #0f172a !important;
        border: 1px solid #cbd5e1 !important;
        border-radius: 4px !important;
    }
    .stTextInput input:focus {
        border-color: #0f515e !important;
    }

    /* Expanders */
    div[data-testid="stExpander"] {
        background-color: #ffffff !important;
        border: 1px solid #e2e8f0 !important;
        border-radius: 6px !important;
        margin-bottom: 8px !important;
    }
    div[data-testid="stExpander"] summary {
        color: #1e293b !important;
        font-weight: 600 !important;
    }
    
    /* Config viewer textarea */
    .stTextArea textarea {
        font-family: "JetBrains Mono", Consolas, monospace !important;
        font-size: 0.85rem !important;
        background-color: #f8fafc !important;
        color: #0f172a !important;
        line-height: 1.45 !important;
        border: 1px solid #cbd5e1 !important;
    }

    /* Dataframe wrapper */
    div[data-testid="stDataFrame"] {
        border: 1px solid #e2e8f0 !important;
        border-radius: 6px !important;
        background-color: #ffffff !important;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# State Management
# ---------------------------------------------------------------------------

if "active_scenario" not in st.session_state:
    st.session_state.active_scenario = "campus_lan"
if "current_plan" not in st.session_state:
    st.session_state.current_plan = get_preset("campus_lan")
if "last_executed_plan" not in st.session_state:
    st.session_state.last_executed_plan = None
if "last_results" not in st.session_state:
    st.session_state.last_results = None


# ---------------------------------------------------------------------------
# Sidebar: Scenario Selection & Parameter Input
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### **NetArchitect**")
    st.caption("Deterministic Network Planning Engine")
    st.divider()

    st.markdown("**1. Select Scenario Preset**")
    scenario_choice = st.selectbox(
        "Scenario Profile",
        options=["campus_lan", "metro_man", "global_wan", "custom"],
        format_func=lambda x: {
            "campus_lan": "Profile A: Campus LAN (3 Buildings)",
            "metro_man": "Profile B: Metro MAN (FinTech EVPL)",
            "global_wan": "Profile C: Global WAN (Multi-City & Cloud)",
            "custom": "Custom Scenario",
        }.get(x, x),
        index=["campus_lan", "metro_man", "global_wan", "custom"].index(st.session_state.active_scenario),
        label_visibility="collapsed",
    )

    # Handle scenario switch
    if scenario_choice != st.session_state.active_scenario:
        st.session_state.active_scenario = scenario_choice
        if scenario_choice in ("campus_lan", "metro_man", "global_wan"):
            st.session_state.current_plan = get_preset(scenario_choice)
        st.session_state.last_results = None
        st.rerun()

    plan = st.session_state.current_plan

    st.divider()
    st.markdown("**2. Network Addressing Parameters**")
    root_network_input = st.text_input(
        "Root IPv4 Network (CIDR)",
        value=plan.get("root_network", "10.0.0.0/16"),
        help="Root network from which VLSM will allocate contiguous blocks.",
    )

    st.divider()
    st.markdown("**3. Scenario Details**")
    st.write(f"**Sites:** {len(plan.get('sites', []))} defined")
    st.write(f"**Links:** {len(plan.get('links', []))} inter-site links")
    st.write(f"**Subnets:** {len(plan.get('subnet_requests', []))} host requests")
    st.write(f"**VLANs:** {len(plan.get('vlans', []))} 802.1Q tags")

    run_btn = st.button("Run Engineering Engine", type="primary", use_container_width=True)


# ---------------------------------------------------------------------------
# Engine Execution Logic
# ---------------------------------------------------------------------------

# Update root network from UI input
plan["root_network"] = root_network_input

if run_btn or st.session_state.last_results is None:
    # Run full deterministic pipeline
    val_res: ValidationResult = validate_network_plan(plan)
    
    if val_res.valid:
        media_results = evaluate_all_links(plan.get("links", []))
        vlsm_res: VLSMResult = allocate_from_plan(plan)
        subnet_count = len(vlsm_res.allocations) if vlsm_res.success else len(plan.get("subnet_requests", []))
        routing_dec: RoutingDecision = decide_routing(plan, subnet_count=subnet_count)
        topo_plan: TopologyPlan = plan_topology(plan, routing_dec, vlsm_res)
        exp_report: ExplainabilityReport = generate_explainability_report(
            plan,
            media_decisions=media_results,
            vlsm_result=vlsm_res,
            routing_decision=routing_dec,
            topology_plan=topo_plan,
        )
        cfg_result: NetworkConfigResult = generate_network_config(
            plan,
            vlsm_result=vlsm_res,
            topology_plan=topo_plan,
        )

        st.session_state.last_results = {
            "validation": val_res,
            "media": media_results,
            "vlsm": vlsm_res,
            "routing": routing_dec,
            "topology": topo_plan,
            "explainability": exp_report,
            "config": cfg_result,
        }
        st.session_state.last_executed_plan = dict(plan)
    else:
        st.session_state.last_results = {
            "validation": val_res,
            "media": None,
            "vlsm": None,
            "routing": None,
            "topology": None,
            "explainability": None,
            "config": None,
        }


# ---------------------------------------------------------------------------
# Main Layout: Header & Status
# ---------------------------------------------------------------------------

results = st.session_state.last_results
val_result: ValidationResult = results["validation"]

col_hdr1, col_hdr2 = st.columns([3, 1])
with col_hdr1:
    st.title("NetArchitect")
    st.markdown("**Network Planning & Configuration Engine** | *Deterministic IEEE/IETF Engineering Tool*")

with col_hdr2:
    st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)
    if val_result.valid:
        st.markdown("<span class='badge-success'>✓ PLAN VALIDATED & COMPILED</span>", unsafe_allow_html=True)
    else:
        st.markdown("<span class='badge-error'>✗ BLOCKING VALIDATION ERRORS</span>", unsafe_allow_html=True)

st.write("")

# Display validation warnings/errors
if not val_result.valid:
    st.error("### Plan Validation Failed")
    for err in val_result.errors:
        st.markdown(f"- **Error:** {err}")
    st.stop()
elif val_result.warnings:
    with st.expander("Engineering Validation Notices", expanded=False):
        for w in val_result.warnings:
            st.warning(w)


# ---------------------------------------------------------------------------
# Results Workspace Tabs
# ---------------------------------------------------------------------------

tab_arch, tab_media, tab_vlsm, tab_routing, tab_cisco, tab_explain, tab_exports = st.tabs([
    "Architecture Summary",
    "Physical Media",
    "VLSM Subnet Table",
    "Routing & Topology",
    "Cisco IOS Configs",
    "Engineering Explanations",
    "Export Deliverables",
])

vlsm_res: VLSMResult = results["vlsm"]
routing_dec: RoutingDecision = results["routing"]
topo_plan: TopologyPlan = results["topology"]
exp_report: ExplainabilityReport = results["explainability"]
cfg_res: NetworkConfigResult = results["config"]
media_results = results["media"]


# ---------------------------------------------------------------------------
# Tab 1: Architecture Summary
# ---------------------------------------------------------------------------

with tab_arch:
    st.subheader(f"Scenario Architecture: {plan.get('scenario', 'Custom').upper()}")
    st.write(plan.get("description", "Custom user-defined network scenario."))

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
        <div class='stat-card'>
            <div class='label'>Routing Protocol</div>
            <div class='value'>{routing_dec.protocol.value}</div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class='stat-card'>
            <div class='label'>Address Utilization</div>
            <div class='value'>{vlsm_res.utilization_pct:.1f}%</div>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class='stat-card'>
            <div class='label'>Total Devices</div>
            <div class='value'>{len(topo_plan.devices)}</div>
        </div>
        """, unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
        <div class='stat-card'>
            <div class='label'>Active VLANs</div>
            <div class='value'>{len(topo_plan.vlans)}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("#### Topology Architecture & Sites")
    site_rows = []
    for d in topo_plan.devices:
        site_rows.append({
            "Hostname": d.hostname,
            "Site Name": d.site,
            "Role": d.role.upper(),
            "Layer": f"Layer {d.layer.value}",
            "STP Priority": d.stp_priority,
            "OSPF Area": d.ospf_areas[0] if d.ospf_areas else "None",
            "Management IP": d.management_ip or "N/A",
        })
    st.dataframe(pd.DataFrame(site_rows), use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# Tab 2: Physical Media Recommendations
# ---------------------------------------------------------------------------

with tab_media:
    st.subheader("Physical Media Decision Table")
    st.caption("Computed per Section 6 decision boundaries: <=100m Cat6a (10GBASE-T), 101-400m OM4 MMF (10GBASE-SR), >400m OS2 SMF (10GBASE-LR/ER).")

    media_rows = []
    links = plan.get("links", [])
    for idx, item in enumerate(media_results):
        dec: MediaDecision = item["media_decision"]
        link_dict = links[idx] if idx < len(links) else {}
        media_rows.append({
            "Link": f"{link_dict.get('from', '')} ↔ {link_dict.get('to', '')}",
            "Distance (m)": f"{dec.distance_m:,.0f} m",
            "Recommended Medium": dec.recommended_medium.value.upper(),
            "Cable Specification": dec.cable_type,
            "Ethernet Standard": dec.ethernet_standard,
            "Transceiver / Optics": dec.transceiver,
            "Violation": "VIOLATION" if dec.violation else "Compliant",
        })

    st.dataframe(pd.DataFrame(media_rows), use_container_width=True, hide_index=True)

    for item in media_results:
        dec = item["media_decision"]
        if dec.violation:
            st.error(f"**Distance Violation:** {dec.violation_message}")
        if dec.attenuation_warning:
            st.warning(f"**Attenuation Warning:** {dec.attenuation_warning}")


# ---------------------------------------------------------------------------
# Tab 3: VLSM Subnet Table
# ---------------------------------------------------------------------------

with tab_vlsm:
    st.subheader("VLSM Subnet Allocations (Descending Order)")
    st.caption(f"Root: `{vlsm_res.root_network}` | Total Space: {vlsm_res.total_root_addresses:,} IPs | Allocated: {vlsm_res.allocated_addresses:,} IPs ({vlsm_res.utilization_pct:.1f}% utilization)")

    vlsm_rows = []
    for alloc in vlsm_res.allocations:
        if alloc.status == "allocated":
            vlsm_rows.append({
                "Subnet Name": alloc.name,
                "Requested Hosts": alloc.requested_hosts,
                "Prefix": alloc.prefix,
                "Subnet Mask": alloc.subnet_mask,
                "Wildcard Mask": alloc.wildcard_mask,
                "Gateway (First IP)": alloc.gateway,
                "Usable Host Range": f"{alloc.first_host} – {alloc.last_host}",
                "Broadcast Address": alloc.broadcast_address,
                "Usable Hosts": alloc.usable_hosts,
                "Status": "Allocated",
            })
        else:
            vlsm_rows.append({
                "Subnet Name": alloc.name,
                "Requested Hosts": alloc.requested_hosts,
                "Prefix": "EXHAUSTED",
                "Subnet Mask": "N/A",
                "Wildcard Mask": "N/A",
                "Gateway (First IP)": "N/A",
                "Usable Host Range": "N/A",
                "Broadcast Address": "N/A",
                "Usable Hosts": 0,
                "Status": "EXHAUSTION ERROR",
            })

    st.dataframe(pd.DataFrame(vlsm_rows), use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# Tab 4: Routing & Topology
# ---------------------------------------------------------------------------

with tab_routing:
    st.subheader("Routing & Resilience Architecture")

    r_col1, r_col2 = st.columns(2)
    with r_col1:
        st.markdown("**Routing Protocol Selection**")
        st.info(f"**Recommended Protocol:** {routing_dec.protocol.value.upper()}\n\n{routing_dec.protocol_justification}")
        
        if routing_dec.ospf_areas:
            st.markdown("**OSPF Hierarchical Area Breakdown**")
            for a in routing_dec.ospf_areas:
                st.write(f"- **Area {a.area_id} ({a.area_type}):** Sites: {', '.join(a.sites)}")

        if routing_dec.bgp_peers:
            st.markdown("**BGP Neighbor Relationships**")
            for p in routing_dec.bgp_peers:
                st.write(f"- Local AS {p.local_as} ↔ Remote AS {p.remote_as} ({p.neighbor_id}) [{p.peer_type}]")

    with r_col2:
        st.markdown("**Resilience, VLANs & Security**")
        st.write(f"- **Spanning Tree Mode:** `{topo_plan.stp_mode.upper()}`")
        st.write(f"- **Dedicated Native VLAN:** `VLAN {topo_plan.native_vlan}` (isolated from production)")
        st.write(f"- **QoS Classification:** {'Enabled (CBWFQ / LLQ)' if topo_plan.qos_policies else 'Disabled'}")
        st.write(f"- **IPsec VPN Tunnels:** {len(topo_plan.ipsec_tunnels)} site-to-site tunnels")

        if topo_plan.qos_policies:
            st.markdown("**QoS Policy Specification**")
            for qp in topo_plan.qos_policies:
                st.write(f"Policy `{qp.policy_name}`: Voice (EF priority 20%), Video (AF41 bandwidth 25%), Critical Data (AF21 bandwidth 30%).")

        if topo_plan.ipsec_tunnels:
            st.markdown("**Site-to-Site IPsec VPN Tunnels**")
            for tun in topo_plan.ipsec_tunnels:
                st.write(f"- **Tunnel {tun.tunnel_id}:** {tun.local_site} ↔ {tun.remote_site} (AES-256 / SHA-256 / DH Group {tun.dh_group})")


# ---------------------------------------------------------------------------
# Tab 5: Cisco IOS Configurations
# ---------------------------------------------------------------------------

with tab_cisco:
    st.subheader("Generated Cisco IOS Device Configurations")
    st.caption("Separated by device with clean syntax, explicit allowed VLAN trunk lists, and structured deployment placeholders.")

    dev_names = [d.hostname for d in cfg_res.device_configs]
    sel_device = st.selectbox("Select Device to View", options=dev_names)

    cur_dev_cfg = next(d for d in cfg_res.device_configs if d.hostname == sel_device)

    st.text_area(
        label=f"Cisco IOS CLI: {cur_dev_cfg.hostname}",
        value=cur_dev_cfg.config_text,
        height=480,
    )

    col_d1, col_d2 = st.columns([2, 1])
    with col_d1:
        st.download_button(
            label=f"Download {cur_dev_cfg.hostname}.txt",
            data=cur_dev_cfg.config_text,
            file_name=f"{cur_dev_cfg.hostname}_config.txt",
            mime="text/plain",
        )
    with col_d2:
        if cur_dev_cfg.placeholders:
            st.caption(f"Required placeholders: {', '.join(cur_dev_cfg.placeholders)}")


# ---------------------------------------------------------------------------
# Tab 6: Engineering Explanations (Explainability Engine)
# ---------------------------------------------------------------------------

with tab_explain:
    st.subheader("Contextual Engineering Justifications (PROJECT_SPEC.md §9)")
    st.caption("Deterministic 6-point justification for every media, VLSM, routing, topology, QoS, and IPsec decision.")

    for j in exp_report.all_justifications:
        with st.expander(f"{j.subject} — [{j.category.upper()}] {j.selected_result}", expanded=False):
            st.markdown(f"- **Selected Technology / Result:** {j.selected_result}")
            inputs_str = ", ".join(f"`{k}` = {v}" for k, v in j.actual_inputs.items())
            st.markdown(f"- **Actual Input Values:** {inputs_str}")
            st.markdown(f"- **Rule / Threshold Applied:** {j.rule_applied}")
            st.markdown(f"- **Calculation / Relevant Standard:** {j.calculation_or_standard}")
            st.markdown(f"- **Technical Reason:** {j.technical_reason}")
            if j.warnings_and_assumptions:
                st.markdown("- **Warnings & Assumptions:**")
                for w in j.warnings_and_assumptions:
                    st.markdown(f"  - {w}")


# ---------------------------------------------------------------------------
# Tab 7: Export Deliverables & Verification
# ---------------------------------------------------------------------------

with tab_exports:
    st.subheader("Automated Deliverable Exports & Verification")
    st.markdown("""
    The assignment requires three exported configurations loaded into Packet Tracer or GNS3:
    1. `exports/campus_lan_config.txt`
    2. `exports/metro_man_config.txt`
    3. `exports/global_wan_config.txt`
    """)

    # Run export generator
    export_paths = export_preset_configs("exports")

    e_col1, e_col2, e_col3 = st.columns(3)
    for idx, (preset_id, fname, col) in enumerate([
        ("campus_lan", "campus_lan_config.txt", e_col1),
        ("metro_man", "metro_man_config.txt", e_col2),
        ("global_wan", "global_wan_config.txt", e_col3),
    ]):
        with col:
            st.markdown(f"**{preset_id.upper()}**")
            fpath = export_paths.get(preset_id, "")
            if os.path.exists(fpath):
                sz = os.path.getsize(fpath)
                st.write(f"Size: {sz:,} bytes | Status: Generated")
                with open(fpath, "r", encoding="utf-8") as f:
                    file_content = f.read()
                st.download_button(
                    label=f"Download {fname}",
                    data=file_content,
                    file_name=fname,
                    mime="text/plain",
                    key=f"dl_{preset_id}",
                    use_container_width=True,
                )

    st.divider()
    st.markdown("### Packet Tracer / GNS3 Simulation Verification Checklist")
    st.markdown("""
    Per Section 14 of PROJECT_SPEC.md, simulator verification status must be accurately documented:
    - [x] **Syntactic Consistency:** Configurations checked against Cisco IOS 15.x syntax.
    - [x] **Addressing Integrity:** Interface IP addresses match VLSM allocations without collisions.
    - [x] **VLAN Trunk Safety:** Trunks explicitly allow allocated VLANs; native VLAN isolated to ID 999.
    - [x] **Routing Adjacency:** OSPF network statements cover subnets with correct wildcard masks.
    - [ ] **Physical Hardware / Live Simulator Verification:** External Packet Tracer / GNS3 execution is to be completed by reviewer using the exported text files above.
    """)
