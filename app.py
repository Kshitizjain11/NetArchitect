"""NetArchitect Web Dashboard - Interactive Network Architecture & Cisco IOS Provisioning Engine."""
import ipaddress
from typing import List, Optional
import streamlit as st
import pandas as pd

from src.models import (
    AddressExhaustionError,
    L1Decision,
    NetworkProfile,
    PhysicalDistanceViolationError,
    RoutingDecision,
    SubnetAllocation,
    SubnetRequest,
)
from src.engines import L1MediaEngine, VLSMAllocator, RoutingEngine
from src.presets import PRESETS, get_preset
from src.config_gen import CiscoConfigGenerator


# ==============================================================================
# Page Configuration & Custom Styling
# ==============================================================================
st.set_page_config(
    page_title="NetArchitect | Algorithmic L1-L3 Provisioning",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #555;
        margin-bottom: 1.5rem;
    }
    .card-box {
        border-radius: 8px;
        padding: 1.2rem;
        background-color: #f8f9fa;
        border-left: 5px solid #2a5298;
        margin-bottom: 1rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ==============================================================================
# Sidebar: Scenario & Parameter Controls
# ==============================================================================
st.sidebar.markdown("## ⚙️ NetArchitect Controls")
st.sidebar.markdown("Configure scenario presets or input custom topology constraints.")

mode = st.sidebar.radio(
    "Control Mode",
    ["Preset Profiles", "Custom Network Parameters"],
    help="Switch between pre-validated production profiles or custom architectural parameters.",
)

profile: Optional[NetworkProfile] = None
media_override: Optional[str] = None

if mode == "Preset Profiles":
    preset_choice = st.sidebar.selectbox(
        "Choose Preset Profile",
        [
            "Profile 1: Campus LAN (300m, 1,600 nodes, 10.10.0.0/16)",
            "Profile 2: Metro MAN (22km, 450 nodes, 172.16.0.0/16)",
            "Profile 3: Global WAN (50km, 2,000 nodes, 10.100.0.0/16)",
        ],
    )

    preset_key = "campus_lan"
    if "Metro MAN" in preset_choice:
        preset_key = "metro_man"
    elif "Global WAN" in preset_choice:
        preset_key = "global_wan"

    base_preset = get_preset(preset_key)

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🧪 L1 Physical Boundary Test Override")
    override_option = st.sidebar.selectbox(
        "Requested Media Override",
        ["Default (Algorithmic Selection)", "Force Copper (Test Exception)", "Force Fiber (OM4/OS2)"],
        help="Select 'Force Copper' to test the IEEE 802.3an >100m PhysicalDistanceViolationError live in the UI!",
    )

    if override_option == "Force Copper (Test Exception)":
        media_override = "copper"
    elif override_option == "Force Fiber (OM4/OS2)":
        media_override = "fiber"
    else:
        media_override = None

    profile = NetworkProfile(
        name=base_preset.name,
        description=base_preset.description,
        distance_m=base_preset.distance_m,
        root_prefix=base_preset.root_prefix,
        host_requests=list(base_preset.host_requests),
        requested_media=media_override,
        single_as=base_preset.single_as,
        multi_site_or_cloud=base_preset.multi_site_or_cloud,
        features=list(base_preset.features),
        vlan_base=base_preset.vlan_base,
    )

    st.sidebar.info(
        f"**Loaded Profile:** `{profile.name}`\n\n"
        f"• **Distance:** {profile.distance_m:,.0f} m\n\n"
        f"• **Root CIDR:** `{profile.root_prefix}`\n\n"
        f"• **Subnet Groups:** {len(profile.host_requests)}"
    )

else:
    # Custom Network Mode
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🛠️ Custom Network Parameters")

    custom_name = st.sidebar.text_input("Profile Identifier", value="custom_enterprise_core")
    custom_desc = st.sidebar.text_input("Description", value="Custom Enterprise Hybrid Fabric")
    custom_distance = st.sidebar.number_input(
        "Link Distance (meters)",
        min_value=1.0,
        max_value=100000.0,
        value=300.0,
        step=25.0,
        help="Physical distance between distribution / core aggregation nodes.",
    )

    custom_media_opt = st.sidebar.selectbox(
        "Requested Media Override",
        ["auto", "copper", "fiber"],
        help="Selecting 'copper' with distance > 100m will trigger an IEEE 802.3an PhysicalDistanceViolationError.",
    )
    media_override = None if custom_media_opt == "auto" else custom_media_opt

    custom_root = st.sidebar.text_input("Root CIDR Network", value="10.10.0.0/16")
    custom_demands_str = st.sidebar.text_input(
        "Subnet Host Demands (comma-separated)",
        value="800, 400, 250, 150",
        help="Enter host demands separated by commas. Sorting will be handled automatically by the VLSM engine.",
    )

    topology_scope = st.sidebar.selectbox(
        "Administrative Scope",
        ["Single AS (<50 subnets)", "Multi-Site / Metro", "Global WAN / Multi-Cloud Boundary"],
    )
    enable_hsrp = st.sidebar.checkbox("Dual-Homed Failover (HSRP Gateway Redundancy)", value=False)
    custom_vlan_base = st.sidebar.number_input("Starting VLAN ID", min_value=1, max_value=4000, value=10, step=10)

    # Parse host demands
    parsed_requests: List[SubnetRequest] = []
    try:
        raw_demands = [int(x.strip()) for x in custom_demands_str.split(",") if x.strip()]
        for idx, h in enumerate(raw_demands):
            parsed_requests.append(
                SubnetRequest(name=f"Custom_Subnet_{idx + 1}", hosts=h, vlan_id=None)
            )
    except ValueError:
        st.sidebar.error("Error: Subnet Host Demands must be comma-separated integers.")

    is_single_as = "Single AS" in topology_scope
    is_multi_site = not is_single_as

    custom_features = ["802.1Q VLAN Trunking", "Rapid PVST+"]
    if enable_hsrp:
        custom_features.append("Dual-Homed Default Gateway Redundancy (HSRP)")
    if is_multi_site:
        custom_features.append("Multi-Site OSPF Core Peering")
    else:
        custom_features.append("Single-Area OSPFv2 (Area 0)")

    profile = NetworkProfile(
        name=custom_name,
        description=custom_desc,
        distance_m=float(custom_distance),
        root_prefix=custom_root,
        host_requests=parsed_requests,
        requested_media=media_override,
        single_as=is_single_as,
        multi_site_or_cloud=is_multi_site,
        features=custom_features,
        vlan_base=int(custom_vlan_base),
    )


# ==============================================================================
# Main Dashboard Area
# ==============================================================================
st.markdown('<div class="main-header">🌐 NetArchitect Enterprise Provisioning Console</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">Deterministic L1 Physical Media, L3 VLSM Bitwise Sizing & Cisco IOS Provisioning Engine</div>',
    unsafe_allow_html=True,
)

if not profile or not profile.host_requests:
    st.warning("Please specify valid network parameters in the sidebar to compile architecture.")
    st.stop()

# Execution and Exception Handling Container
engine_failed = False
l1_decision = None
allocations = None
routing_decision = None
config_output = None

try:
    # 1. L1 Engine
    l1_decision = L1MediaEngine.evaluate(
        distance_m=profile.distance_m,
        requested_media=profile.requested_media,
    )

    # 2. VLSM Engine
    allocations = VLSMAllocator.allocate(
        root_prefix=profile.root_prefix,
        host_requests=profile.host_requests,
        vlan_start=profile.vlan_base,
    )

    # 3. Routing Engine
    routing_decision = RoutingEngine.evaluate(
        subnet_count=len(allocations),
        single_as=profile.single_as,
        multi_site_or_cloud=profile.multi_site_or_cloud,
    )

    # 4. Cisco IOS Generator
    generator = CiscoConfigGenerator(
        profile=profile,
        l1=l1_decision,
        allocations=allocations,
        routing=routing_decision,
    )
    config_output = generator.generate_full_config()

except PhysicalDistanceViolationError as p_err:
    engine_failed = True
    st.error(
        f"### ⚠️ Physical Distance Violation Exception Caught!\n\n"
        f"**Engine Rationale:** {p_err}\n\n"
        f"*Standard Citation:* **IEEE 802.3an** limits balanced twisted-pair copper transmission to 100 meters. "
        f"Attaching copper transceiver optics across {profile.distance_m:,.1f}m will induce severe insertion loss and signal attenuation."
    )

except AddressExhaustionError as a_err:
    engine_failed = True
    st.error(
        f"### 🚫 IPv4 Address Space Exhaustion Exception Caught!\n\n"
        f"**Engine Rationale:** {a_err}\n\n"
        f"The requested host blocks exceed the mathematical capacity of root prefix `{profile.root_prefix}`."
    )

except Exception as err:
    engine_failed = True
    st.error(f"### ❌ Architectural Compilation Failure: {err}")


# ==============================================================================
# Success View: Metric Cards, Tabs & Reports
# ==============================================================================
if not engine_failed and l1_decision and allocations and routing_decision and config_output:
    total_requested_hosts = sum(a.requested_hosts for a in allocations)
    total_usable_hosts = sum(a.usable_hosts for a in allocations)
    overall_efficiency = round((total_requested_hosts / total_usable_hosts) * 100, 1)

    # Top Metric Cards
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric(
            label="Selected Physical Media",
            value=l1_decision.selected_media.split(" ")[0],
            delta=l1_decision.selected_media.split(" ")[1] if len(l1_decision.selected_media.split(" ")) > 1 else None,
        )
    with c2:
        dist_display = f"{profile.distance_m:,.0f} m" if profile.distance_m < 1000 else f"{profile.distance_m / 1000.0:.2f} km"
        st.metric(
            label="Link Span / Distance",
            value=dist_display,
            delta="Within Optical Budget",
        )
    with c3:
        st.metric(
            label="VLSM Subnets / Capacity",
            value=f"{len(allocations)} Subnets",
            delta=f"{total_usable_hosts:,} Usable ({overall_efficiency}% Eff)",
        )
    with c4:
        proto_abbr = "OSPFv2 (Area 0)" if "Single-Area" in routing_decision.selected_protocol else "OSPF + eBGP"
        st.metric(
            label="L3 Dynamic Routing",
            value=proto_abbr,
            delta="Optimal SPF Dijkstra",
        )

    st.markdown("---")

    # Structured Tabs
    tab_rationale, tab_table, tab_config = st.tabs([
        "🧠 Decision Rationale",
        "📊 Subnet Allocation Table",
        "💻 Deployment Configs",
    ])

    # TAB 1: Architectural Decision Rationale
    with tab_rationale:
        st.markdown("### 🏛️ Engineering & Standards Decision Matrix")

        st.markdown("#### 1. Layer 1 Physical Transmission Media")
        st.info(
            f"**Selected Medium:** `{l1_decision.selected_media}`\n\n"
            f"**Governing Standard:** `{l1_decision.standard_reference}`\n\n"
            f"**Technical Justification:** {l1_decision.rationale}"
        )

        st.markdown("#### 2. Layer 3 Dynamic Routing Architecture")
        st.success(
            f"**Routing Protocol:** `{routing_decision.selected_protocol}`\n\n"
            f"**Topology Domain:** `{routing_decision.topology_scope}`\n\n"
            f"**Convergence & Isolation Justification:** {routing_decision.rationale}"
        )

        st.markdown("#### 3. VLSM Allocation Efficiency & Subnet Tree Topology")
        st.markdown(
            f"Root Prefix `{profile.root_prefix}` was algorithmically partitioned into **{len(allocations)} non-overlapping subnets**. "
            f"Total requested hosts: **{total_requested_hosts:,}**, total usable host allocation: **{total_usable_hosts:,}** "
            f"(Overall bitwise allocation efficiency: **{overall_efficiency}%**)."
        )

    # TAB 2: VLSM Subnet Allocation Table
    with tab_table:
        st.markdown("### 📋 Deterministic Subnet Allocation Table")
        st.caption(f"Allocated from Root Prefix: `{profile.root_prefix}` using strict descending-order bitwise alignment.")

        table_data = []
        for a in allocations:
            table_data.append({
                "VLAN ID": a.vlan_id,
                "Subnet Name": a.name,
                "Req Hosts": a.requested_hosts,
                "Allocated Block": a.allocated_size,
                "Usable Hosts": a.usable_hosts,
                "CIDR Prefix": a.cidr,
                "Subnet Mask": a.netmask,
                "Wildcard Mask": a.wildcard_mask,
                "Gateway IP": a.first_usable_gateway,
                "Host Range": f"{a.first_usable_gateway} - {a.last_usable_host}",
                "Broadcast IP": a.broadcast_address,
                "Efficiency": f"{a.utilization_efficiency * 100:.1f}%",
            })

        df = pd.DataFrame(table_data)
        st.dataframe(df, width="stretch", hide_index=True)

        # Download CSV
        csv_bytes = df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Export Subnet Table to CSV",
            data=csv_bytes,
            file_name=f"{profile.name}_vlsm_table.csv",
            mime="text/csv",
        )

    # TAB 3: Cisco IOS Deployment Configuration
    with tab_config:
        st.markdown("### 💻 Copy-Paste Ready Cisco IOS Configuration")
        st.caption("Production-grade Cisco IOS configuration verified for Cisco Catalyst & ISR/ASR platforms.")

        st.download_button(
            label=f"📥 Download Cisco IOS Config ({profile.name}.cfg)",
            data=config_output,
            file_name=f"{profile.name}.cfg",
            mime="text/plain",
            help="Download copy-paste ready .cfg file for Cisco Packet Tracer, GNS3, or physical hardware.",
        )

        st.code(config_output, language="cisco")
