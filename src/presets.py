"""Preset network engineering profiles for NetArchitect."""
from typing import Dict
from src.models import NetworkProfile, SubnetRequest


PRESETS: Dict[str, NetworkProfile] = {
    "campus_lan": NetworkProfile(
        name="campus_lan",
        description="Profile 1: High-Density 3-Building Enterprise Campus LAN",
        distance_m=300.0,
        root_prefix="10.10.0.0/16",
        host_requests=[
            SubnetRequest(name="BldgA_Engineering", hosts=800, vlan_id=10),
            SubnetRequest(name="BldgB_Operations", hosts=400, vlan_id=20),
            SubnetRequest(name="BldgC_Administration", hosts=250, vlan_id=30),
            SubnetRequest(name="Campus_VoIP_WLAN", hosts=150, vlan_id=40),
        ],
        requested_media=None,
        single_as=True,
        multi_site_or_cloud=False,
        features=[
            "PoE 802.3bt Access Layer",
            "802.1Q VLAN Trunking",
            "Rapid Per-VLAN Spanning Tree (PVRST+)",
            "Single-Area OSPFv2 (Area 0)",
        ],
        vlan_base=10,
    ),
    "metro_man": NetworkProfile(
        name="metro_man",
        description="Profile 2: Low-Latency Financial Metro Area Network (HQ + 2 Remote Colos)",
        distance_m=22000.0,  # 22 km
        root_prefix="172.16.0.0/16",
        host_requests=[
            SubnetRequest(name="HQ_TradingFloor", hosts=200, vlan_id=100),
            SubnetRequest(name="Colo1_UltraLowLatency", hosts=150, vlan_id=200),
            SubnetRequest(name="Colo2_DisasterRecovery", hosts=100, vlan_id=300),
        ],
        requested_media=None,
        single_as=False,
        multi_site_or_cloud=True,
        features=[
            "Ethernet Virtual Private Line (EVPL)",
            "Sub-5ms Strict Priority Queuing (QoS)",
            "Dual-Homed Default Gateway Redundancy (HSRP)",
            "Multi-Site OSPF Core Peering",
        ],
        vlan_base=100,
    ),
    "global_wan": NetworkProfile(
        name="global_wan",
        description="Profile 3: Global Distributed Enterprise WAN (4 Cities + Multi-Cloud VPC)",
        distance_m=50000.0,  # 50 km inter-pop baseline
        root_prefix="10.100.0.0/16",
        host_requests=[
            SubnetRequest(name="Hub_Region_A", hosts=600, vlan_id=10),
            SubnetRequest(name="Hub_Region_B", hosts=500, vlan_id=20),
            SubnetRequest(name="Hub_Region_C", hosts=450, vlan_id=30),
            SubnetRequest(name="Branch_Region_D", hosts=300, vlan_id=40),
            SubnetRequest(name="Cloud_VPC_Interconnect", hosts=150, vlan_id=50),
        ],
        requested_media=None,
        single_as=False,
        multi_site_or_cloud=True,
        features=[
            "IPsec VPN Tunnel Overlay (AES-256-GCM)",
            "Hierarchical Multi-Area OSPF + eBGP Peering",
            "Autonomous System Boundary Isolation",
            "CIDR Supernetting & Route Summarization",
        ],
        vlan_base=10,
    ),
}


def get_preset(name: str) -> NetworkProfile:
    """Retrieve a copy of a registered network profile preset."""
    if name not in PRESETS:
        valid = ", ".join(PRESETS.keys())
        raise KeyError(f"Unknown preset profile '{name}'. Valid profiles: {valid}")
    return PRESETS[name]
