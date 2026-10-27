"""
profiles/presets.py
-------------------
Defines the three mandatory scenario presets for NetArchitect.

Each preset is a plain Python dictionary that matches the NetworkPlanRequest
schema defined in engine/input_validation.py.  The presets are authoritative
data for the three assignment profiles; they must not be edited to paper over
engine defects.

Profiles
--------
A  Campus LAN   – three-building enterprise campus
B  Metro MAN    – FinTech headquarters + two remote sites
C  Global WAN   – four cities + cloud VPC, IoT fleet
"""

from __future__ import annotations
from typing import Any

# ---------------------------------------------------------------------------
# Scenario identifiers
# ---------------------------------------------------------------------------
CAMPUS_LAN = "campus_lan"
METRO_MAN = "metro_man"
GLOBAL_WAN = "global_wan"
CUSTOM = "custom"

SCENARIO_IDS = (CAMPUS_LAN, METRO_MAN, GLOBAL_WAN, CUSTOM)

# ---------------------------------------------------------------------------
# Profile A — Campus LAN
# ---------------------------------------------------------------------------
CAMPUS_LAN_PRESET: dict[str, Any] = {
    "scenario": CAMPUS_LAN,
    "description": (
        "Three-building enterprise campus, <400 m inter-building distances, "
        "~1,600 endpoints, PoE APs, IEEE 802.1Q VLANs, RSTP, single-area OSPF."
    ),
    # --- Sites / topology ---
    "sites": [
        {"name": "Building A", "role": "core"},
        {"name": "Building B", "role": "distribution"},
        {"name": "Building C", "role": "distribution"},
    ],
    # --- Inter-site links (metres) ---
    "links": [
        {"from": "Building A", "to": "Building B", "distance_m": 180, "bandwidth_gbps": 10},
        {"from": "Building A", "to": "Building C", "distance_m": 320, "bandwidth_gbps": 10},
        {"from": "Building B", "to": "Building C", "distance_m": 250, "bandwidth_gbps": 10},
    ],
    # --- Addressing ---
    "root_network": "10.10.0.0/16",
    "subnet_requests": [
        {"name": "Staff_A",       "required_hosts": 400},
        {"name": "Staff_B",       "required_hosts": 350},
        {"name": "Staff_C",       "required_hosts": 300},
        {"name": "Wireless_A",    "required_hosts": 150},
        {"name": "Wireless_B",    "required_hosts": 150},
        {"name": "Wireless_C",    "required_hosts": 150},
        {"name": "Management",    "required_hosts": 30},
        {"name": "Servers",       "required_hosts": 60},
    ],
    # --- Layer 2 ---
    "vlans": [
        {"id": 10, "name": "Staff_A",    "description": "Staff Building A"},
        {"id": 20, "name": "Staff_B",    "description": "Staff Building B"},
        {"id": 30, "name": "Staff_C",    "description": "Staff Building C"},
        {"id": 40, "name": "Wireless_A", "description": "Wireless Building A"},
        {"id": 50, "name": "Wireless_B", "description": "Wireless Building B"},
        {"id": 60, "name": "Wireless_C", "description": "Wireless Building C"},
        {"id": 70, "name": "Mgmt",       "description": "Management"},
        {"id": 80, "name": "Servers",    "description": "Server VLAN"},
    ],
    "native_vlan": 999,
    "stp_mode": "rstp",
    # --- Routing ---
    "routing_protocol": "ospf",
    "ospf_areas": [{"area_id": 0, "networks": "all"}],
    # --- Special features ---
    "poe_required": True,
    "qos_required": False,
    "ipsec_vpn_required": False,
    "redundancy": "rstp",
}

# ---------------------------------------------------------------------------
# Profile B — Metro MAN
# ---------------------------------------------------------------------------
METRO_MAN_PRESET: dict[str, Any] = {
    "scenario": METRO_MAN,
    "description": (
        "FinTech HQ + two remote sites, 15–35 km apart, ~450 users, "
        "OS2 single-mode fiber, EVPL, <5 ms latency target, QoS, dual-homed failover."
    ),
    "sites": [
        {"name": "HQ",      "role": "hub"},
        {"name": "Site_B",  "role": "spoke"},
        {"name": "Site_C",  "role": "spoke"},
    ],
    "links": [
        {"from": "HQ", "to": "Site_B", "distance_m": 15_000, "bandwidth_gbps": 10},
        {"from": "HQ", "to": "Site_C", "distance_m": 35_000, "bandwidth_gbps": 10},
        # Redundant cross-link for dual-homed failover
        {"from": "Site_B", "to": "Site_C", "distance_m": 28_000, "bandwidth_gbps": 1},
    ],
    "root_network": "172.16.0.0/20",
    "subnet_requests": [
        {"name": "HQ_Users",     "required_hosts": 250},
        {"name": "SiteB_Users",  "required_hosts": 100},
        {"name": "SiteC_Users",  "required_hosts": 80},
        {"name": "Management",   "required_hosts": 20},
    ],
    "vlans": [
        {"id": 10, "name": "HQ_Users",    "description": "HQ user VLAN"},
        {"id": 20, "name": "SiteB_Users", "description": "Site B user VLAN"},
        {"id": 30, "name": "SiteC_Users", "description": "Site C user VLAN"},
        {"id": 40, "name": "Mgmt",        "description": "Management"},
        {"id": 50, "name": "QoS_Voice",   "description": "Voice/Real-time traffic"},
    ],
    "native_vlan": 999,
    "stp_mode": "rstp",
    "routing_protocol": "ospf",
    "ospf_areas": [{"area_id": 0, "networks": "all"}],
    "evpl_connectivity": True,
    "latency_target_ms": 5,
    "latency_note": (
        "Sub-5 ms latency cannot be guaranteed by configuration alone. "
        "Physical propagation delay for 35 km of fiber is approximately 0.175 ms. "
        "End-to-end latency depends on carrier SLA, queuing, and CPE processing. "
        "Validate against carrier SLA after deployment."
    ),
    "poe_required": False,
    "qos_required": True,
    "ipsec_vpn_required": False,
    "redundancy": "dual_homed",
}

# ---------------------------------------------------------------------------
# Profile C — Global WAN
# ---------------------------------------------------------------------------
GLOBAL_WAN_PRESET: dict[str, Any] = {
    "scenario": GLOBAL_WAN,
    "description": (
        "Four cities + cloud VPC, ~2,000 IoT devices/scanners, "
        "IPsec VPN, Multi-Area OSPF and/or BGP, route summarization."
    ),
    "sites": [
        {"name": "City_Mumbai",    "role": "hub",   "asn": 65001},
        {"name": "City_Delhi",     "role": "spoke", "asn": 65001},
        {"name": "City_Bangalore", "role": "spoke", "asn": 65001},
        {"name": "City_Chennai",   "role": "spoke", "asn": 65001},
        {"name": "Cloud_VPC",      "role": "cloud", "asn": 65002},
    ],
    "links": [
        {"from": "City_Mumbai",    "to": "City_Delhi",     "distance_m": 1_400_000, "bandwidth_gbps": 1},
        {"from": "City_Mumbai",    "to": "City_Bangalore",  "distance_m": 980_000,  "bandwidth_gbps": 1},
        {"from": "City_Mumbai",    "to": "City_Chennai",    "distance_m": 1_330_000, "bandwidth_gbps": 1},
        {"from": "City_Mumbai",    "to": "Cloud_VPC",       "distance_m": 0,        "bandwidth_gbps": 10},  # Cloud connection — no physical distance
        {"from": "City_Delhi",     "to": "City_Bangalore",  "distance_m": 2_150_000, "bandwidth_gbps": 1},
    ],
    "root_network": "192.168.0.0/16",
    "subnet_requests": [
        # Per-site user/IoT subnets
        {"name": "Mumbai_Users",      "required_hosts": 500},
        {"name": "Delhi_Users",       "required_hosts": 400},
        {"name": "Bangalore_Users",   "required_hosts": 350},
        {"name": "Chennai_Users",     "required_hosts": 300},
        {"name": "IoT_Mumbai",        "required_hosts": 600},
        {"name": "IoT_Delhi",         "required_hosts": 500},
        {"name": "IoT_Bangalore",     "required_hosts": 450},
        {"name": "IoT_Chennai",       "required_hosts": 400},
        {"name": "Cloud_VPC_Segment", "required_hosts": 250},
        {"name": "Management",        "required_hosts": 30},
        {"name": "VPN_Tunnels",       "required_hosts": 14},
    ],
    "vlans": [
        {"id": 10,  "name": "Mumbai_Users",    "description": "Mumbai staff"},
        {"id": 20,  "name": "Delhi_Users",     "description": "Delhi staff"},
        {"id": 30,  "name": "Bangalore_Users", "description": "Bangalore staff"},
        {"id": 40,  "name": "Chennai_Users",   "description": "Chennai staff"},
        {"id": 100, "name": "IoT_Fleet",       "description": "IoT devices and scanners"},
        {"id": 200, "name": "Mgmt",            "description": "OOB Management"},
        {"id": 300, "name": "VPN_Overlay",     "description": "IPsec tunnel overlay"},
    ],
    "native_vlan": 999,
    "stp_mode": "rstp",
    "routing_protocol": "multi_area_ospf_bgp",
    "ospf_areas": [
        {"area_id": 0,  "networks": ["City_Mumbai"]},
        {"area_id": 1,  "networks": ["City_Delhi"]},
        {"area_id": 2,  "networks": ["City_Bangalore"]},
        {"area_id": 3,  "networks": ["City_Chennai"]},
    ],
    "bgp_peers": [
        {"local_as": 65001, "remote_as": 65002, "neighbor": "Cloud_VPC", "description": "Cloud VPC eBGP peer"},
    ],
    "route_summarization": True,
    "poe_required": False,
    "qos_required": False,
    "ipsec_vpn_required": True,
    "redundancy": "ipsec_failover",
}

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
PRESETS: dict[str, dict[str, Any]] = {
    CAMPUS_LAN: CAMPUS_LAN_PRESET,
    METRO_MAN:  METRO_MAN_PRESET,
    GLOBAL_WAN: GLOBAL_WAN_PRESET,
}


def get_preset(scenario_id: str) -> dict[str, Any]:
    """Return a deep copy of the named preset so callers cannot mutate it."""
    import copy
    if scenario_id not in PRESETS:
        raise KeyError(
            f"Unknown scenario '{scenario_id}'. "
            f"Valid choices: {list(PRESETS.keys())}"
        )
    return copy.deepcopy(PRESETS[scenario_id])


def get_all_presets() -> dict[str, dict[str, Any]]:
    """Return deep copies of all registered presets."""
    import copy
    return copy.deepcopy(PRESETS)

