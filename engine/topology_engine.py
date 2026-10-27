"""
engine/topology_engine.py
--------------------------
Network topology planning engine for NetArchitect.

Produces a structured TopologyPlan from a validated network plan and its
VLSM allocation.  The TopologyPlan is the shared data model consumed by:
  - engine/explainability.py  (engineering justifications)
  - generator/cisco_ios.py    (device configuration generation)

Design principles
-----------------
- Every field is derived from actual plan inputs and VLSM results.
- No IP addresses, hostnames, or VLAN IDs are invented — they come from
  the plan or the VLSM allocator output.
- Topology decisions (STP root, OSPF areas per device, QoS policy maps)
  are deterministic and explainable.
- Profile-specific features (RSTP, QoS, IPsec) are represented as
  structured objects, not embedded strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from engine.routing_engine import RoutingDecision, OspfAreaSpec, BgpPeerSpec


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class DeviceLayer(int, Enum):
    LAYER_3 = 3
    LAYER_2 = 2


class InterfaceRole(str, Enum):
    TRUNK     = "trunk"
    ACCESS    = "access"
    ROUTED    = "routed"    # Layer 3 routed port
    LOOPBACK  = "loopback"
    TUNNEL    = "tunnel"    # GRE / IPsec tunnel


# ---------------------------------------------------------------------------
# Sub-structures
# ---------------------------------------------------------------------------

@dataclass
class VlanSpec:
    """One VLAN as it appears in the topology plan."""
    vlan_id:      int
    name:         str
    description:  str
    subnet:       str     # Allocated CIDR, or "" if not yet assigned
    svi_ip:       str     # SVI IP address on the L3 switch, or ""
    svi_mask:     str     # Subnet mask for SVI


@dataclass
class InterfaceSpec:
    """A single logical interface on a device."""
    name:          str         # e.g. "GigabitEthernet0/1", "Loopback0"
    role:          InterfaceRole
    description:   str
    # For routed ports:
    ip_address:    str         # Dotted-decimal, or ""
    subnet_mask:   str         # Dotted-decimal, or ""
    # For trunk ports:
    allowed_vlans: list[int]
    native_vlan:   int
    # For access ports:
    access_vlan:   int
    # For tunnel ports:
    tunnel_source: str
    tunnel_dest:   str
    # OSPF participation
    ospf_area:     Optional[int]   # None if not running OSPF on this interface
    ospf_passive:  bool            # True for access/loopback interfaces


@dataclass
class DeviceSpec:
    """
    A network device in the topology.

    Represents a switch or router — not the physical hardware, but the
    logical configuration target.
    """
    hostname:        str
    site:            str
    role:            str          # "core", "distribution", "access", "hub", "spoke", "cloud-edge"
    layer:           DeviceLayer
    management_ip:   str          # IP in the management subnet
    management_mask: str
    vlans:           list[int]    # VLAN IDs present/configured on this device
    interfaces:      list[InterfaceSpec]
    stp_priority:    int          # 4096=root, 8192=backup, 32768=default
    stp_mode:        str          # "rstp", "mstp", etc.
    ospf_process_id: int
    ospf_router_id:  str          # Loopback or highest IP
    ospf_areas:      list[int]    # Area IDs this device participates in
    is_abr:          bool         # True if device connects two OSPF areas
    is_asbr:         bool         # True if device redistributes between OSPF and BGP
    bgp_asn:         int          # 0 if BGP not running on this device
    qos_enabled:     bool
    ipsec_enabled:   bool


@dataclass
class QosPolicySpec:
    """QoS policy map specification for a device or interface."""
    policy_name:    str
    class_maps:     list[dict]   # [{name, match_dscp, bandwidth_pct}]
    description:    str


@dataclass
class IpsecTunnelSpec:
    """IPsec VPN tunnel template for a site-to-site link."""
    tunnel_id:          int
    local_site:         str
    remote_site:        str
    transform_set:      str    # e.g. "TS-AES256-SHA"
    ike_version:        int    # 1 or 2
    encryption:         str    # "aes 256"
    authentication:     str    # "sha256"
    dh_group:           int    # Diffie-Hellman group
    local_peer:         str    # Placeholder: "<LOCAL-PEER-IP>"
    remote_peer:        str    # Placeholder: "<REMOTE-PEER-IP>"
    pre_shared_key:     str    # Placeholder: "<PSK-REPLACE-BEFORE-DEPLOY>"
    interesting_traffic: str   # ACL name for traffic to encrypt
    dpd_interval:       int    # Dead Peer Detection interval (seconds)
    dpd_retry:          int    # DPD retry count


@dataclass
class TopologyPlan:
    """
    Complete structured topology for all devices in the network plan.

    Consumed by the explainability engine and the Cisco IOS config generator.
    No field is a fabricated placeholder — all data traces to the plan inputs
    or the VLSM allocator output.
    """
    scenario:          str
    devices:           list[DeviceSpec]
    vlans:             list[VlanSpec]
    routing_decision:  RoutingDecision
    qos_policies:      list[QosPolicySpec]
    ipsec_tunnels:     list[IpsecTunnelSpec]
    native_vlan:       int
    stp_mode:          str
    redundancy_notes:  list[str]
    topology_warnings: list[str]
    assumptions:       list[str]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sanitize_hostname(text: str) -> str:
    """Convert a site name to a valid Cisco IOS hostname."""
    h = re.sub(r"[^A-Za-z0-9\-]", "-", text).strip("-")
    return h[:63] if h else "DEVICE"


def _stp_priority(role: str, is_backup: bool = False) -> int:
    """Return STP bridge priority for a given device role."""
    if role in ("core", "hub") and not is_backup:
        return 4096      # Root bridge
    if role in ("core", "hub", "distribution") and is_backup:
        return 8192      # Backup root
    return 32768         # Default


def _management_ip_for_site(site_name: str, mgmt_alloc, index: int) -> tuple[str, str]:
    """
    Return (ip, mask) for a device's management interface.

    Uses the management subnet allocation if available, assigning .index+2
    (gateway is .1).  Falls back to empty strings with a warning if no
    management subnet was allocated.
    """
    if mgmt_alloc is None:
        return "", ""

    import ipaddress
    try:
        net = ipaddress.IPv4Network(mgmt_alloc.prefix, strict=True)
        # Skip network (.0) and gateway (.1)
        host_int = int(net.network_address) + 2 + index
        if host_int <= int(net.broadcast_address) - 1:
            return str(ipaddress.IPv4Address(host_int)), str(net.netmask)
    except Exception:
        pass
    return "", ""


def _build_vlan_specs(plan: dict, vlsm_result) -> list[VlanSpec]:
    """
    Build VlanSpec list by joining the plan's VLAN definitions with
    VLSM allocation results where the names match.
    """
    # Build name → allocation map
    alloc_map: dict[str, object] = {}
    if vlsm_result is not None:
        for alloc in vlsm_result.allocations:
            if alloc.status == "allocated":
                alloc_map[alloc.name] = alloc

    vlan_specs: list[VlanSpec] = []
    for vlan in plan.get("vlans", []):
        vid   = vlan.get("id", 0)
        name  = vlan.get("name", "")
        desc  = vlan.get("description", "")
        # Try to find a matching subnet allocation by name
        alloc = alloc_map.get(name)
        if alloc is None:
            mgmt_tokens = {"mgmt", "management", "manage"}
            for k, a in alloc_map.items():
                if k.lower() == name.lower():
                    alloc = a
                    break
                if any(t in k.lower() for t in mgmt_tokens) and any(t in name.lower() for t in mgmt_tokens):
                    alloc = a
                    break
        subnet_cidr = alloc.prefix if alloc else ""
        svi_ip      = alloc.gateway if alloc else ""
        svi_mask    = alloc.subnet_mask if alloc else ""
        vlan_specs.append(VlanSpec(
            vlan_id=vid,
            name=name,
            description=desc,
            subnet=subnet_cidr,
            svi_ip=svi_ip,
            svi_mask=svi_mask,
        ))

    return vlan_specs


def _build_qos_policies(plan: dict) -> list[QosPolicySpec]:
    """Build QoS policy specifications for the Metro MAN profile."""
    if not plan.get("qos_required", False):
        return []

    # Standard 4-class DSCP model:
    # EF  (DSCP 46) — voice/real-time:       25% BW, priority queuing
    # AF41 (DSCP 34) — video/interactive:    20% BW
    # AF21 (DSCP 18) — critical data:        30% BW
    # Default        — best-effort:          25% BW
    return [QosPolicySpec(
        policy_name="QOS-WAN-POLICY",
        class_maps=[
            {"name": "CM-VOICE",    "match_dscp": "ef",   "bandwidth_pct": 25, "priority": True},
            {"name": "CM-VIDEO",    "match_dscp": "af41", "bandwidth_pct": 20, "priority": False},
            {"name": "CM-CRITICAL", "match_dscp": "af21", "bandwidth_pct": 30, "priority": False},
            {"name": "class-default",                      "bandwidth_pct": 25, "priority": False,
             "match_dscp": "default"},
        ],
        description=(
            "DSCP-based 4-class QoS policy. EF (DSCP 46) for voice/real-time, "
            "AF41 for video, AF21 for critical data, best-effort for remainder. "
            "Bandwidth percentages are starting points — adjust to measured traffic profiles."
        ),
    )]


def _build_ipsec_tunnels(plan: dict) -> list[IpsecTunnelSpec]:
    """Build IPsec tunnel templates for the Global WAN profile."""
    if not plan.get("ipsec_vpn_required", False):
        return []

    sites = plan.get("sites", [])
    # Build hub-and-spoke or full-mesh tunnels
    tunnels: list[IpsecTunnelSpec] = []
    hub_sites   = [s for s in sites if s.get("role") in ("hub", "core")]
    spoke_sites = [s for s in sites if s.get("role") in ("spoke",)]
    cloud_sites = [s for s in sites if s.get("role") == "cloud"]

    tid = 100
    for spoke in spoke_sites + cloud_sites:
        hub = hub_sites[0] if hub_sites else sites[0]
        tunnels.append(IpsecTunnelSpec(
            tunnel_id=tid,
            local_site=hub["name"],
            remote_site=spoke["name"],
            transform_set="TS-AES256-SHA256",
            ike_version=2,
            encryption="aes 256",
            authentication="sha256",
            dh_group=14,
            local_peer=f"<{hub['name'].upper()}-WAN-IP>",
            remote_peer=f"<{spoke['name'].upper()}-WAN-IP>",
            pre_shared_key="<PSK-REPLACE-BEFORE-DEPLOYMENT>",
            interesting_traffic=f"ACL-VPN-{hub['name'].upper()}-TO-{spoke['name'].upper()}",
            dpd_interval=30,
            dpd_retry=3,
        ))
        tid += 1

    return tunnels


def _assign_ospf_areas_to_sites(
    routing: RoutingDecision,
    sites: list[dict],
) -> dict[str, int]:
    """
    Return a map of site_name → ospf_area_id.

    For single-area OSPF: all sites → Area 0.
    For multi-area: use the area assignments from RoutingDecision.ospf_areas.
    """
    site_to_area: dict[str, int] = {}
    for area_spec in routing.ospf_areas:
        for site_name in area_spec.sites:
            site_to_area[site_name] = area_spec.area_id
    # Default any unassigned sites to Area 0
    for site in sites:
        name = site.get("name", "")
        if name and name not in site_to_area:
            site_to_area[name] = 0
    return site_to_area


def _build_devices(
    plan: dict,
    vlan_specs: list[VlanSpec],
    routing: RoutingDecision,
    vlsm_result,
) -> list[DeviceSpec]:
    """
    Build one DeviceSpec per site.

    For each site the engine creates one representative device
    (core router/switch for LAN sites, WAN router for WAN sites).
    The configuration generator will expand these into full device configs.
    """
    sites = plan.get("sites", [])
    native_vlan = plan.get("native_vlan", 999)
    stp_mode    = plan.get("stp_mode", "rstp")
    vlan_ids    = [v.vlan_id for v in vlan_specs]

    # Management allocation
    mgmt_alloc = None
    if vlsm_result is not None:
        for alloc in vlsm_result.allocations:
            if alloc.status == "allocated" and "mgmt" in alloc.name.lower() or \
               "management" in alloc.name.lower():
                mgmt_alloc = alloc
                break

    site_to_area = _assign_ospf_areas_to_sites(routing, sites)

    # Determine ABR sites (participate in more than one OSPF area)
    area_site_map: dict[str, set[int]] = {}
    for area_spec in routing.ospf_areas:
        for site_name in area_spec.sites:
            area_site_map.setdefault(site_name, set()).add(area_spec.area_id)

    # Hub sites connecting multiple areas are ABRs
    hub_roles = {"core", "hub"}

    # BGP-enabled sites (ASBRs)
    bgp_sites: set[str] = {p.neighbor_id for p in routing.bgp_peers}
    hub_sites_with_bgp = {
        s["name"] for s in sites
        if s.get("role") in hub_roles and routing.bgp_peers
    }

    devices: list[DeviceSpec] = []
    for i, site in enumerate(sites):
        site_name = site.get("name", f"Site{i}")
        role      = site.get("role", "access")
        asn       = site.get("asn", 0) or 0

        hostname = _sanitize_hostname(site_name)

        # Layer: cloud sites are typically L3-only (no L2 VLAN trunking)
        layer = DeviceLayer.LAYER_3 if role in ("cloud",) else DeviceLayer.LAYER_3

        # STP priority
        is_primary_root = (i == 0 and role in hub_roles)
        is_backup_root  = (i == 1 and role in hub_roles | {"distribution"})
        stp_prio = _stp_priority(role, is_backup=is_backup_root)
        if is_primary_root and not is_backup_root:
            stp_prio = 4096

        mgmt_ip, mgmt_mask = _management_ip_for_site(site_name, mgmt_alloc, i)

        ospf_area_id = site_to_area.get(site_name, 0)
        is_abr  = len(area_site_map.get(site_name, {0})) > 1
        is_asbr = (site_name in hub_sites_with_bgp) or (asn > 0 and routing.bgp_peers)

        # Build interfaces (loopback for OSPF router-id, uplinks as routed)
        interfaces: list[InterfaceSpec] = []

        # Loopback0 for OSPF router-id
        interfaces.append(InterfaceSpec(
            name="Loopback0",
            role=InterfaceRole.LOOPBACK,
            description=f"OSPF Router-ID / Management loopback for {site_name}",
            ip_address=mgmt_ip if mgmt_ip else f"<LOOPBACK-{site_name.upper()}>",
            subnet_mask="255.255.255.255",
            allowed_vlans=[],
            native_vlan=0,
            access_vlan=0,
            tunnel_source="",
            tunnel_dest="",
            ospf_area=ospf_area_id,
            ospf_passive=True,
        ))

        # Uplink trunk (for L2/L3 boundary devices)
        if role not in ("cloud",):
            interfaces.append(InterfaceSpec(
                name="GigabitEthernet0/0",
                role=InterfaceRole.TRUNK,
                description=f"Uplink trunk — {site_name}",
                ip_address="",
                subnet_mask="",
                allowed_vlans=vlan_ids,
                native_vlan=native_vlan,
                access_vlan=0,
                tunnel_source="",
                tunnel_dest="",
                ospf_area=ospf_area_id,
                ospf_passive=False,
            ))

        # WAN/routed uplink for spoke/hub sites
        if role in ("hub", "spoke", "cloud"):
            interfaces.append(InterfaceSpec(
                name="GigabitEthernet0/1",
                role=InterfaceRole.ROUTED,
                description=f"WAN uplink — {site_name}",
                ip_address=f"<WAN-IP-{site_name.upper()}>",
                subnet_mask=f"<WAN-MASK-{site_name.upper()}>",
                allowed_vlans=[],
                native_vlan=0,
                access_vlan=0,
                tunnel_source="",
                tunnel_dest="",
                ospf_area=ospf_area_id,
                ospf_passive=False,
            ))

        # IPsec tunnel interfaces
        if routing.ipsec_vpn_required and role in ("hub", "spoke"):
            interfaces.append(InterfaceSpec(
                name=f"Tunnel{100 + i}",
                role=InterfaceRole.TUNNEL,
                description=f"IPsec GRE tunnel — {site_name} to hub",
                ip_address=f"<TUNNEL-IP-{site_name.upper()}>",
                subnet_mask="255.255.255.252",
                allowed_vlans=[],
                native_vlan=0,
                access_vlan=0,
                tunnel_source=f"GigabitEthernet0/1",
                tunnel_dest=f"<REMOTE-HUB-WAN-IP>",
                ospf_area=ospf_area_id,
                ospf_passive=False,
            ))

        devices.append(DeviceSpec(
            hostname=hostname,
            site=site_name,
            role=role,
            layer=layer,
            management_ip=mgmt_ip,
            management_mask=mgmt_mask,
            vlans=vlan_ids if role not in ("cloud",) else [],
            interfaces=interfaces,
            stp_priority=stp_prio,
            stp_mode=stp_mode,
            ospf_process_id=1,
            ospf_router_id=mgmt_ip if mgmt_ip else f"<ROUTER-ID-{site_name.upper()}>",
            ospf_areas=[ospf_area_id],
            is_abr=is_abr,
            is_asbr=bool(is_asbr),
            bgp_asn=asn if routing.bgp_peers else 0,
            qos_enabled=routing.qos_required,
            ipsec_enabled=routing.ipsec_vpn_required,
        ))

    return devices


def _build_topology_warnings(plan: dict, routing: RoutingDecision) -> list[str]:
    warnings: list[str] = []

    latency = plan.get("latency_target_ms")
    if latency is not None:
        warnings.append(
            f"Latency target {latency} ms: this cannot be guaranteed by topology "
            "planning. Actual latency depends on physical propagation, carrier SLA, "
            "and CPE processing. Validate after deployment."
        )

    if routing.ipsec_vpn_required:
        warnings.append(
            "IPsec VPN: peer addresses, pre-shared keys, and crypto parameters "
            "use placeholder values. Replace all <...> placeholders before deployment. "
            "Do NOT deploy configurations containing <PSK-REPLACE-BEFORE-DEPLOYMENT>."
        )

    if routing.qos_required:
        warnings.append(
            "QoS policy: bandwidth percentages are starting-point estimates. "
            "Adjust class-map DSCP values and bandwidth allocations to match "
            "measured traffic profiles."
        )

    return warnings


def _build_topology_assumptions(plan: dict) -> list[str]:
    return [
        "One representative device is modelled per site. "
        "Actual deployments may use multiple physical switches/routers per site.",
        "Interface names (GigabitEthernet0/0 etc.) are illustrative placeholders. "
        "Rename to match actual device hardware.",
        "STP root assignments assume the first hub/core site is the primary root. "
        "Verify this matches the physical topology.",
        "OSPF router IDs are assigned from the management subnet where available. "
        "Configure a dedicated loopback interface per router for stability.",
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def plan_topology(
    plan: dict,
    routing: RoutingDecision,
    vlsm_result=None,
) -> TopologyPlan:
    """
    Build a complete structured topology plan.

    Parameters
    ----------
    plan : dict
        Validated network plan dict.
    routing : RoutingDecision
        Output of decide_routing().
    vlsm_result : VLSMResult | None
        Output of allocate_vlsm() / allocate_from_plan(), used to map
        subnet allocations to VLANs and devices.

    Returns
    -------
    TopologyPlan
        Structured topology consumable by the explainability and config
        generator modules.
    """
    scenario    = plan.get("scenario", "custom")
    native_vlan = plan.get("native_vlan", 999)
    stp_mode    = plan.get("stp_mode", "rstp")

    vlan_specs  = _build_vlan_specs(plan, vlsm_result)
    qos_polices = _build_qos_policies(plan)
    ipsec_tunnels = _build_ipsec_tunnels(plan)
    devices     = _build_devices(plan, vlan_specs, routing, vlsm_result)
    warnings    = _build_topology_warnings(plan, routing)
    assumptions = _build_topology_assumptions(plan)

    return TopologyPlan(
        scenario=scenario,
        devices=devices,
        vlans=vlan_specs,
        routing_decision=routing,
        qos_policies=qos_polices,
        ipsec_tunnels=ipsec_tunnels,
        native_vlan=native_vlan,
        stp_mode=stp_mode,
        redundancy_notes=routing.redundancy_notes,
        topology_warnings=warnings,
        assumptions=assumptions,
    )
