"""
generator/cisco_ios.py
-----------------------
Deterministic Cisco IOS configuration generator for NetArchitect.

Produces syntactically valid, consistent Cisco IOS CLI configuration files
directly from validated network plans, VLSM subnet allocations, and topology plans.

Design & Compliance Rules (PROJECT_SPEC.md Section 10):
--------------------------------------------------------
1. Use actual allocated addresses and topology data.
2. Maintain strict consistency between VLAN IDs, interface roles, IP addresses,
   and routing statements.
3. NEVER invent credentials, private keys, peer IPs, or unavailable parameters.
   Use explicit structured placeholders (e.g. <ENTER_ENABLE_SECRET>, <REMOTE_PEER_IP>).
4. Explicitly allow only specified VLANs on trunks (NEVER unrestricted 'all').
5. Isolate native VLAN to an unused dedicated ID (e.g. VLAN 999).
6. Enable RSTP with deterministic root priorities (4096 on primary, 8192 on backup).
7. Generate SVIs on Layer 3 devices with first usable IP (gateway) from VLSM.
8. Generate OSPF network statements with accurate wildcard masks and area IDs.
9. Implement QoS class-maps and policy-maps for Metro MAN EVPL links.
10. Implement IKEv2 / IPsec VPN tunnel configurations for Global WAN.
11. Document target platform assumptions and deployment prerequisites.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from engine.vlsm_allocator import VLSMResult, SubnetAllocation, allocate_from_plan
from engine.routing_engine import RoutingDecision, ProtocolChoice, decide_routing
from engine.topology_engine import (
    TopologyPlan,
    DeviceSpec,
    InterfaceSpec,
    InterfaceRole,
    DeviceLayer,
    VlanSpec,
    QosPolicySpec,
    IpsecTunnelSpec,
    plan_topology,
)
from profiles.presets import get_preset


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class CiscoDeviceConfig:
    """
    Generated Cisco IOS configuration for a single network device.
    """
    hostname: str
    site: str
    role: str
    config_text: str
    placeholders: list[str] = field(default_factory=list)
    platform_assumptions: list[str] = field(default_factory=list)


@dataclass
class NetworkConfigResult:
    """
    Complete configuration bundle for all devices in a network plan.
    """
    scenario: str
    device_configs: list[CiscoDeviceConfig] = field(default_factory=list)
    combined_config_text: str = ""
    placeholders_summary: list[str] = field(default_factory=list)
    export_filename: str = ""


# ---------------------------------------------------------------------------
# Device Config Generator
# ---------------------------------------------------------------------------

def generate_device_config(
    device: DeviceSpec,
    topology: TopologyPlan,
    vlsm_result: Optional[VLSMResult] = None,
) -> CiscoDeviceConfig:
    """
    Generate the complete Cisco IOS configuration for a single device.
    """
    lines: list[str] = []
    placeholders: list[str] = []
    assumptions: list[str] = []

    # 1. Header & Platform Assumptions
    lines.append("!" + "=" * 70)
    lines.append(f"! NetArchitect Cisco IOS Configuration")
    lines.append(f"! Device:   {device.hostname}")
    lines.append(f"! Site:     {device.site} (Role: {device.role.upper()})")
    lines.append(f"! Scenario: {topology.scenario}")
    lines.append(f"! Layer:    Layer {device.layer.value} Device")
    lines.append("!" + "=" * 70)
    lines.append("!")
    lines.append("! PLATFORM ASSUMPTIONS & NOTES:")
    lines.append("! 1. Target platform: Cisco IOS 15.x / IOS-XE 16.x or 17.x.")
    lines.append("! 2. Review all bracketed placeholders '<...>' before deployment.")
    lines.append("! 3. Verify interface module designations (e.g., GigabitEthernet vs TenGigabitEthernet).")
    lines.append("!")

    assumptions.append("Target platform is Cisco IOS-XE / IOS 15.x; interface names assume GigabitEthernet.")
    assumptions.append("All credentials and public WAN IPs use structured placeholders that must be set before live deployment.")

    # 2. Base System Settings
    lines.append("! --- BASE SYSTEM CONFIGURATION ---")
    lines.append(f"hostname {device.hostname}")
    lines.append("no ip domain-lookup")
    lines.append("service password-encryption")
    lines.append("enable secret <ENTER_SECURE_ENABLE_SECRET>")
    placeholders.append("<ENTER_SECURE_ENABLE_SECRET>")
    lines.append("ip routing" if device.layer == DeviceLayer.LAYER_3 else "no ip routing")
    lines.append("!")

    # 3. Spanning Tree Protocol (STP)
    if device.role not in ("cloud",):
        lines.append("! --- SPANNING TREE PROTOCOL (IEEE 802.1w) ---")
        lines.append(f"spanning-tree mode {topology.stp_mode}")
        if device.stp_priority < 32768:
            lines.append(f"spanning-tree vlan 1-4094 priority {device.stp_priority}")
            lines.append(f"! Device priority {device.stp_priority} configured for root/backup root deterministic placement.")
        else:
            lines.append(f"! Default bridge priority {device.stp_priority} maintained for non-root bridge.")
        lines.append("spanning-tree portfast default")
        lines.append("spanning-tree portfast bpduguard default")
        lines.append("!")

    # 4. VLAN Creation & Naming (Layer 2 / Layer 3 boundary)
    if device.vlans and device.role not in ("cloud",):
        lines.append("! --- VLAN DATABASE ---")
        vlan_map = {v.vlan_id: v for v in topology.vlans}
        for vid in sorted(device.vlans):
            vspec = vlan_map.get(vid)
            lines.append(f"vlan {vid}")
            if vspec and vspec.name:
                lines.append(f" name {vspec.name}")
            else:
                lines.append(f" name VLAN_{vid}")
        # Always configure dedicated Native VLAN
        if topology.native_vlan not in device.vlans:
            lines.append(f"vlan {topology.native_vlan}")
            lines.append(" name ISOLATED_NATIVE_VLAN")
        lines.append("!")

    # 5. Interfaces Configuration
    lines.append("! --- INTERFACES CONFIGURATION ---")
    for intf in device.interfaces:
        lines.append(f"interface {intf.name}")
        lines.append(f" description {intf.description}")

        if intf.role == InterfaceRole.LOOPBACK:
            lines.append(f" ip address {intf.ip_address} {intf.subnet_mask}")
            if intf.ip_address.startswith("<"):
                placeholders.append(intf.ip_address)
            lines.append(" no shutdown")

        elif intf.role == InterfaceRole.TRUNK:
            lines.append(" switchport")
            # Note for older Catalyst requiring explicit dot1q encapsulation
            lines.append(" switchport trunk encapsulation dot1q")
            lines.append(" switchport mode trunk")
            lines.append(f" switchport trunk native vlan {topology.native_vlan}")
            # Explicit allowed VLAN list — NEVER unrestricted all
            if intf.allowed_vlans:
                allowed_str = ",".join(str(vid) for vid in sorted(intf.allowed_vlans))
                # Also allow native vlan on trunk
                allowed_with_native = f"{allowed_str},{topology.native_vlan}"
                lines.append(f" switchport trunk allowed vlan {allowed_with_native}")
            else:
                lines.append(f" switchport trunk allowed vlan {topology.native_vlan}")
            lines.append(" switchport nonegotiate")
            lines.append(" no shutdown")

        elif intf.role == InterfaceRole.ACCESS:
            lines.append(" switchport")
            lines.append(" switchport mode access")
            lines.append(f" switchport access vlan {intf.access_vlan}")
            lines.append(" spanning-tree portfast")
            lines.append(" spanning-tree bpduguard enable")
            lines.append(" no shutdown")

        elif intf.role == InterfaceRole.ROUTED:
            if device.layer == DeviceLayer.LAYER_3:
                lines.append(" no switchport")
            lines.append(f" ip address {intf.ip_address} {intf.subnet_mask}")
            if intf.ip_address.startswith("<"):
                placeholders.append(intf.ip_address)
            if intf.subnet_mask.startswith("<"):
                placeholders.append(intf.subnet_mask)
            # Apply QoS policy if enabled on this device and this is a WAN/uplink interface
            if device.qos_enabled and topology.qos_policies:
                policy_name = topology.qos_policies[0].policy_name
                lines.append(f" service-policy output {policy_name}")
            lines.append(" no shutdown")

        elif intf.role == InterfaceRole.TUNNEL:
            lines.append(f" ip address {intf.ip_address} {intf.subnet_mask}")
            if intf.ip_address.startswith("<"):
                placeholders.append(intf.ip_address)
            lines.append(f" tunnel source {intf.tunnel_source}")
            lines.append(f" tunnel destination {intf.tunnel_dest}")
            if intf.tunnel_dest.startswith("<"):
                placeholders.append(intf.tunnel_dest)
            lines.append(" tunnel mode ipsec ipv4")
            lines.append(" tunnel protection ipsec profile IPSEC-PROF-NETARCHITECT")
            lines.append(" no shutdown")

        lines.append("!")

    # 6. Switch Virtual Interfaces (SVIs) on Layer 3 Switches
    if device.layer == DeviceLayer.LAYER_3 and device.role not in ("cloud",):
        vlan_map = {v.vlan_id: v for v in topology.vlans}
        lines.append("! --- SWITCH VIRTUAL INTERFACES (SVIs) ---")
        for vid in sorted(device.vlans):
            vspec = vlan_map.get(vid)
            if vspec and vspec.svi_ip and vspec.svi_mask:
                lines.append(f"interface Vlan{vid}")
                lines.append(f" description Gateway SVI for {vspec.name}")
                lines.append(f" ip address {vspec.svi_ip} {vspec.svi_mask}")
                lines.append(" no shutdown")
                lines.append("!")

    # 7. Management Interface (if present and not already created as a VLAN SVI)
    has_mgmt_svi = any(
        (vspec.vlan_id in device.vlans and any(t in vspec.name.lower() for t in ("mgmt", "management")) and vspec.svi_ip)
        for vspec in topology.vlans
    )
    if device.management_ip and device.management_mask and not has_mgmt_svi:
        lines.append("! --- OUT-OF-BAND / MANAGEMENT SVI ---")
        lines.append("interface Vlan99")
        lines.append(f" description Management Interface for {device.hostname}")
        lines.append(f" ip address {device.management_ip} {device.management_mask}")
        lines.append(" no shutdown")
        lines.append("!")

    # 8. QoS Configuration (Metro MAN profile)
    if device.qos_enabled and topology.qos_policies:
        lines.append("! --- QUALITY OF SERVICE (QoS) POLICIES ---")
        for qos in topology.qos_policies:
            lines.append("class-map match-any CM-VOICE")
            lines.append(" match ip dscp ef")
            lines.append("class-map match-any CM-VIDEO")
            lines.append(" match ip dscp af41")
            lines.append("class-map match-any CM-CRITICAL-DATA")
            lines.append(" match ip dscp af21")
            lines.append("!")
            lines.append(f"policy-map {qos.policy_name}")
            lines.append(" class CM-VOICE")
            lines.append("  priority percent 20")
            lines.append(" class CM-VIDEO")
            lines.append("  bandwidth percent 25")
            lines.append(" class CM-CRITICAL-DATA")
            lines.append("  bandwidth percent 30")
            lines.append(" class class-default")
            lines.append("  fair-queue")
            lines.append("!")

    # 9. IPsec VPN Configuration (Global WAN profile)
    if device.ipsec_enabled and topology.ipsec_tunnels:
        lines.append("! --- IPSEC / IKEv2 SITE-TO-SITE VPN ---")
        lines.append("crypto ikev2 proposal PROP-NETARCHITECT")
        lines.append(" encryption aes-cbc-256")
        lines.append(" integrity sha256")
        lines.append(" group 14")
        lines.append("!")
        lines.append("crypto ikev2 policy POL-NETARCHITECT")
        lines.append(" proposal PROP-NETARCHITECT")
        lines.append("!")

        # Keyrings and profiles for each tunnel involving this site
        for tunnel in topology.ipsec_tunnels:
            if tunnel.local_site == device.site or tunnel.remote_site == device.site:
                peer_label = f"PEER-{tunnel.remote_site if tunnel.local_site == device.site else tunnel.local_site}"
                lines.append(f"crypto ikev2 keyring KR-{peer_label}")
                lines.append(f" peer {peer_label}")
                lines.append(f"  address {tunnel.remote_peer}")
                placeholders.append(tunnel.remote_peer)
                lines.append(f"  pre-shared-key {tunnel.pre_shared_key}")
                placeholders.append(tunnel.pre_shared_key)
                lines.append("!")
                lines.append(f"crypto ikev2 profile PROF-{peer_label}")
                lines.append(f" match identity remote address {tunnel.remote_peer} 255.255.255.255")
                lines.append(" authentication remote pre-share")
                lines.append(" authentication local pre-share")
                lines.append(f" keyring local KR-{peer_label}")
                lines.append(f" dpd {tunnel.dpd_interval} {tunnel.dpd_retry} periodic")
                lines.append("!")

        lines.append("crypto ipsec transform-set TS-NETARCHITECT esp-aes 256 esp-sha256-hmac")
        lines.append(" mode tunnel")
        lines.append("!")
        lines.append("crypto ipsec profile IPSEC-PROF-NETARCHITECT")
        lines.append(" set transform-set TS-NETARCHITECT")
        lines.append(" set ikev2-profile PROF-NETARCHITECT")
        lines.append("!")

    # 10. Routing Configuration (OSPF)
    if device.ospf_areas:
        lines.append("! --- ROUTING PROTOCOL (OSPFv2) ---")
        lines.append(f"router ospf {device.ospf_process_id}")
        lines.append(f" router-id {device.ospf_router_id}")
        if device.ospf_router_id.startswith("<"):
            placeholders.append(device.ospf_router_id)

        # Passive-interface strategy: default passive, enable on transit
        lines.append(" passive-interface default")
        for intf in device.interfaces:
            if intf.role in (InterfaceRole.TRUNK, InterfaceRole.ROUTED, InterfaceRole.TUNNEL):
                lines.append(f" no passive-interface {intf.name}")

        # Network statements from allocated subnets
        vlan_map = {v.vlan_id: v for v in topology.vlans}
        for vid in device.vlans:
            vspec = vlan_map.get(vid)
            if vspec and vspec.subnet and vlsm_result:
                # Find matching allocation to get wildcard mask
                for alloc in vlsm_result.allocations:
                    if alloc.prefix == vspec.subnet:
                        area_id = device.ospf_areas[0]
                        lines.append(f" network {alloc.network_address} {alloc.wildcard_mask} area {area_id}")
                        break

        # If device is an ABR and route summarization is enabled
        if device.is_abr and topology.routing_decision.route_summarization:
            lines.append(" ! Inter-Area Route Summarization on ABR")
            for area_id in device.ospf_areas:
                if area_id != 0:
                    lines.append(f" area {area_id} range <SUMMARY_PREFIX_AREA_{area_id}> <SUMMARY_MASK_AREA_{area_id}>")
                    placeholders.append(f"<SUMMARY_PREFIX_AREA_{area_id}>")
                    placeholders.append(f"<SUMMARY_MASK_AREA_{area_id}>")

        lines.append("!")

    # 11. Routing Configuration (BGP)
    if device.bgp_asn > 0:
        lines.append("! --- EXTERIOR BGP (eBGP) CONFIGURATION ---")
        lines.append(f"router bgp {device.bgp_asn}")
        lines.append(" bgp log-neighbor-changes")
        for peer in topology.routing_decision.bgp_peers:
            peer_ip_placeholder = f"<BGP_NEIGHBOR_IP_{peer.neighbor_id.upper()}>"
            lines.append(f" neighbor {peer_ip_placeholder} remote-as {peer.remote_as}")
            lines.append(f" neighbor {peer_ip_placeholder} description {peer.description}")
            if peer.next_hop_self:
                lines.append(f" neighbor {peer_ip_placeholder} next-hop-self")
            placeholders.append(peer_ip_placeholder)

        # Network advertisements
        if vlsm_result:
            for alloc in vlsm_result.allocations[:3]:  # Advertise primary allocations
                lines.append(f" network {alloc.network_address} mask {alloc.subnet_mask}")

        lines.append("!")

    # 12. Security ACLs & VTY hardening
    lines.append("! --- SECURITY ACCESS-CONTROL & LINE SECURITY ---")
    if device.management_ip:
        lines.append("ip access-list standard ACL-MGMT-INBOUND")
        # Restrict management to management subnet
        mgmt_parts = device.management_ip.split(".")
        mgmt_net = f"{mgmt_parts[0]}.{mgmt_parts[1]}.{mgmt_parts[2]}.0"
        lines.append(f" permit {mgmt_net} 0.0.0.255")
        lines.append(" deny any log")
        lines.append("!")

    lines.append("line con 0")
    lines.append(" exec-timeout 10 0")
    lines.append(" logging synchronous")
    lines.append(" login authentication default")
    lines.append("line vty 0 4")
    lines.append(" exec-timeout 10 0")
    lines.append(" logging synchronous")
    lines.append(" transport input ssh")
    if device.management_ip:
        lines.append(" access-class ACL-MGMT-INBOUND in")
    lines.append("!")
    lines.append("end")
    lines.append("")

    return CiscoDeviceConfig(
        hostname=device.hostname,
        site=device.site,
        role=device.role,
        config_text="\n".join(lines),
        placeholders=sorted(set(placeholders)),
        platform_assumptions=assumptions,
    )


# ---------------------------------------------------------------------------
# Network Config Generator Entrypoints
# ---------------------------------------------------------------------------

def generate_network_config(
    plan: dict,
    vlsm_result: Optional[VLSMResult] = None,
    topology_plan: Optional[TopologyPlan] = None,
) -> NetworkConfigResult:
    """
    Generate the complete configuration bundle for all devices in the network plan.
    """
    scenario = plan.get("scenario", "custom")

    # 1. Resolve VLSM if missing
    if vlsm_result is None and "root_network" in plan and "subnet_requests" in plan:
        vlsm_result = allocate_from_plan(plan)

    # 2. Resolve Routing & Topology if missing
    if topology_plan is None:
        subnet_count = len(vlsm_result.allocations) if vlsm_result else len(plan.get("subnet_requests", []))
        routing = decide_routing(plan, subnet_count=subnet_count)
        topology_plan = plan_topology(plan, routing, vlsm_result)

    # 3. Generate device configs
    device_configs: list[CiscoDeviceConfig] = []
    all_placeholders: set[str] = set()

    for dev in topology_plan.devices:
        dev_cfg = generate_device_config(dev, topology_plan, vlsm_result)
        device_configs.append(dev_cfg)
        all_placeholders.update(dev_cfg.placeholders)

    # 4. Build combined export text
    combined_parts = [
        "!" + "=" * 76,
        f"! NETARCHITECT AUTOMATED CISCO IOS CONFIGURATION EXPORT",
        f"! Scenario:    {scenario.upper()}",
        f"! Generated:   Deterministic NetArchitect Configuration Engine",
        f"! Devices:     {len(device_configs)} devices ({', '.join(d.hostname for d in device_configs)})",
        "!" + "=" * 76,
        "",
    ]

    for dev_cfg in device_configs:
        combined_parts.append(dev_cfg.config_text)
        combined_parts.append("\n" + "!" * 76 + "\n")

    export_map = {
        "campus_lan": "campus_lan_config.txt",
        "metro_man": "metro_man_config.txt",
        "global_wan": "global_wan_config.txt",
    }
    export_filename = export_map.get(scenario, f"{scenario}_config.txt")

    return NetworkConfigResult(
        scenario=scenario,
        device_configs=device_configs,
        combined_config_text="\n".join(combined_parts),
        placeholders_summary=sorted(all_placeholders),
        export_filename=export_filename,
    )


def export_preset_configs(output_dir: str = "exports") -> dict[str, str]:
    """
    Run the 3 mandatory preset profiles through the engine and export their
    complete Cisco IOS configurations to the exports/ directory.

    Per PROJECT_SPEC.md Section 10:
      - exports/campus_lan_config.txt
      - exports/metro_man_config.txt
      - exports/global_wan_config.txt
    """
    os.makedirs(output_dir, exist_ok=True)
    results: dict[str, str] = {}

    presets = [
        ("campus_lan", "campus_lan_config.txt"),
        ("metro_man", "metro_man_config.txt"),
        ("global_wan", "global_wan_config.txt"),
    ]

    for key, filename in presets:
        plan = get_preset(key)
        cfg_result = generate_network_config(plan)
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(cfg_result.combined_config_text)
        results[key] = filepath

    return results
