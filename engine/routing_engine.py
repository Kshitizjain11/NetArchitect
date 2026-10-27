"""
engine/routing_engine.py
------------------------
Deterministic routing and redundancy decision engine for NetArchitect.

Implements the assignment's required routing protocol decision rules and
produces structured output for the explainability engine and the Cisco IOS
configuration generator.

Decision rules (per PROJECT_SPEC.md Section 8)
-----------------------------------------------
1.  Single autonomous system, fewer than 50 subnets: recommend OSPF Area 0.
2.  Multi-site or multi-cloud routing boundary: evaluate Multi-Area OSPF
    or eBGP; explain routing-domain isolation.
3.  Topology overrides subnet count: a WAN topology with cloud sites and
    multiple ASNs requires BGP regardless of subnet count.

Profile-specific requirements
------------------------------
- Campus LAN  : VLANs, RSTP, single-area OSPF.
- Metro MAN   : dual-homed failover, QoS, EVPL, redundant paths, OS2.
- Global WAN  : IPsec VPN, multi-area OSPF + eBGP, route summarization.

Guarantees
----------
- Convergence times and latency values are NEVER guaranteed — only noted
  as engineering considerations.
- All decisions trace back to the inputs used to make them.
- No static/canned decisions — the engine reads the plan fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ProtocolChoice(str, Enum):
    OSPF               = "ospf"
    MULTI_AREA_OSPF    = "multi_area_ospf"
    BGP                = "bgp"
    MULTI_AREA_OSPF_BGP = "multi_area_ospf_bgp"
    STATIC             = "static"


class RedundancyMode(str, Enum):
    NONE          = "none"
    RSTP          = "rstp"
    DUAL_HOMED    = "dual_homed"
    IPSEC_FAILOVER = "ipsec_failover"
    HSRP          = "hsrp"
    VRRP          = "vrrp"


# Subnet count threshold for the single-area OSPF baseline rule.
OSPF_SINGLE_AREA_SUBNET_THRESHOLD = 50


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class OspfAreaSpec:
    """
    Represents one OSPF area with its network assignments and summarization.
    """
    area_id:        int
    area_type:      str          # "backbone" | "normal" | "stub" | "nssa"
    sites:          list[str]    # Site names whose subnets belong to this area
    networks:       list[str]    # Network/prefix strings (populated by config generator)
    summary_routes: list[str]    # Aggregate routes advertised from this area


@dataclass
class BgpPeerSpec:
    """A single BGP neighbor relationship."""
    local_as:    int
    remote_as:   int
    neighbor_id: str           # Peer name/site
    description: str
    peer_type:   str           # "eBGP" | "iBGP"
    next_hop_self: bool        # True for iBGP route reflector clients


@dataclass
class RoutingDecision:
    """
    Fully structured routing protocol decision.

    All fields are computed from actual plan inputs — none are static text.

    Attributes
    ----------
    protocol : ProtocolChoice
        The recommended routing protocol.
    subnet_count : int
        Number of subnets in the plan (one decision factor).
    site_count : int
        Number of sites (one decision factor).
    autonomous_systems : list[int]
        Distinct ASNs found in the plan.
    has_routing_boundary : bool
        True when an inter-AS or cloud routing boundary is present.
    single_area_ospf : bool
        True when all OSPF routers belong to Area 0.
    ospf_areas : list[OspfAreaSpec]
        OSPF area specifications (empty for non-OSPF protocols).
    bgp_peers : list[BgpPeerSpec]
        BGP neighbor specifications (empty when BGP is not used).
    route_summarization : bool
        Whether route summarization is recommended.
    summary_boundary : str
        Description of where summarization should occur, or "".
    redundancy_mode : RedundancyMode
        Recommended redundancy mechanism.
    qos_required : bool
    ipsec_vpn_required : bool
    stp_mode : str
    native_vlan : int
    protocol_justification : str
        Engineering justification from actual input values.
    area_justification : str
        Why single or multiple OSPF areas are appropriate.
    bgp_justification : str
        Why BGP is or is not applicable.
    redundancy_notes : list[str]
        Notes on redundancy configuration and limitations.
    assumptions : list[str]
        Explicit assumptions made by the engine.
    warnings : list[str]
        Non-blocking engineering warnings.
    """
    protocol:               ProtocolChoice
    subnet_count:           int
    site_count:             int
    autonomous_systems:     list[int]
    has_routing_boundary:   bool
    single_area_ospf:       bool
    ospf_areas:             list[OspfAreaSpec]
    bgp_peers:              list[BgpPeerSpec]
    route_summarization:    bool
    summary_boundary:       str
    redundancy_mode:        RedundancyMode
    qos_required:           bool
    ipsec_vpn_required:     bool
    stp_mode:               str
    native_vlan:            int
    protocol_justification: str
    area_justification:     str
    bgp_justification:      str
    redundancy_notes:       list[str]
    assumptions:            list[str]
    warnings:               list[str]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_asns(plan: dict) -> list[int]:
    """Return a sorted list of distinct ASNs found in the sites list."""
    asns: set[int] = set()
    for site in plan.get("sites", []):
        asn = site.get("asn")
        if asn and isinstance(asn, int):
            asns.add(asn)
    return sorted(asns)


def _has_cloud_site(plan: dict) -> bool:
    """True if any site has role='cloud'."""
    return any(s.get("role") == "cloud" for s in plan.get("sites", []))


def _has_routing_boundary(asns: list[int], has_cloud: bool, bgp_peers: list[dict]) -> bool:
    """
    True when an inter-AS or cloud routing boundary is present.

    A routing boundary exists when:
    - There are multiple distinct autonomous systems, OR
    - There is a cloud site (cloud provider typically has its own AS), OR
    - BGP peers are explicitly configured.
    """
    return len(asns) > 1 or has_cloud or len(bgp_peers) > 0


def _choose_protocol(
    subnet_count: int,
    site_count: int,
    has_routing_boundary: bool,
    ospf_areas: list[dict],
    ipsec_required: bool,
    route_summ: bool,
) -> ProtocolChoice:
    """
    Apply the assignment's routing decision rules deterministically.

    Rules (in order of priority):
    1.  Routing boundary (multi-AS / cloud) → requires BGP for inter-AS.
        If also multi-area OSPF internally → MULTI_AREA_OSPF_BGP.
    2.  Multi-area OSPF explicitly configured or many subnets/sites →
        MULTI_AREA_OSPF.
    3.  Baseline: single AS, < 50 subnets → OSPF (single area).
    """
    has_multi_area = len(ospf_areas) > 1

    if has_routing_boundary:
        # Multi-AS or cloud: BGP is required for inter-domain routing.
        # OSPF (possibly multi-area) is still used within each domain.
        return ProtocolChoice.MULTI_AREA_OSPF_BGP

    if has_multi_area or subnet_count >= OSPF_SINGLE_AREA_SUBNET_THRESHOLD:
        return ProtocolChoice.MULTI_AREA_OSPF

    # Default baseline: single AS with < 50 subnets → single-area OSPF.
    return ProtocolChoice.OSPF


def _build_ospf_areas(plan: dict, protocol: ProtocolChoice) -> list[OspfAreaSpec]:
    """Build structured OSPF area specifications from plan data."""
    if protocol == ProtocolChoice.STATIC or protocol == ProtocolChoice.BGP:
        return []

    raw_areas = plan.get("ospf_areas", [])
    if not raw_areas:
        # Default: all networks in Area 0
        return [OspfAreaSpec(
            area_id=0,
            area_type="backbone",
            sites=[s["name"] for s in plan.get("sites", [])],
            networks=[],
            summary_routes=[],
        )]

    result: list[OspfAreaSpec] = []
    for area in raw_areas:
        area_id = area.get("area_id", 0)
        networks_field = area.get("networks", [])
        if isinstance(networks_field, str):
            sites = [networks_field] if networks_field != "all" else \
                    [s["name"] for s in plan.get("sites", [])]
        else:
            sites = list(networks_field)

        area_type = "backbone" if area_id == 0 else "normal"
        result.append(OspfAreaSpec(
            area_id=area_id,
            area_type=area_type,
            sites=sites,
            networks=[],
            summary_routes=[],
        ))

    return result


def _build_bgp_peers(plan: dict, protocol: ProtocolChoice) -> list[BgpPeerSpec]:
    """Build structured BGP peer specifications."""
    if protocol not in (ProtocolChoice.BGP, ProtocolChoice.MULTI_AREA_OSPF_BGP):
        return []

    raw_peers = plan.get("bgp_peers", [])
    result: list[BgpPeerSpec] = []
    for peer in raw_peers:
        local_as  = peer.get("local_as", 0)
        remote_as = peer.get("remote_as", 0)
        peer_type = "eBGP" if local_as != remote_as else "iBGP"
        result.append(BgpPeerSpec(
            local_as=local_as,
            remote_as=remote_as,
            neighbor_id=peer.get("neighbor", ""),
            description=peer.get("description", ""),
            peer_type=peer_type,
            next_hop_self=(peer_type == "iBGP"),
        ))

    return result


def _build_protocol_justification(
    protocol: ProtocolChoice,
    subnet_count: int,
    site_count: int,
    asns: list[int],
    has_routing_boundary: bool,
    has_cloud: bool,
) -> str:
    """Generate a factual protocol justification from actual input values."""
    if protocol == ProtocolChoice.OSPF:
        return (
            f"Single-area OSPF (Area 0) is recommended. "
            f"The plan has {subnet_count} subnet{'s' if subnet_count != 1 else ''} "
            f"(below the {OSPF_SINGLE_AREA_SUBNET_THRESHOLD}-subnet multi-area threshold) "
            f"and {site_count} site{'s' if site_count != 1 else ''} within a single "
            f"autonomous system. "
            "OSPF Area 0 provides link-state convergence, loop-free routing, and "
            "supports VLSM natively. All routers form full adjacencies within Area 0. "
            "Convergence time depends on hello/dead timers and network stability — "
            "it is not guaranteed by protocol selection alone."
        )

    if protocol == ProtocolChoice.MULTI_AREA_OSPF:
        return (
            f"Multi-Area OSPF is recommended. "
            f"The plan has {subnet_count} subnets across {site_count} sites "
            "in a single autonomous system. "
            "Splitting into multiple OSPF areas reduces LSA flooding scope, "
            "confines topology changes to individual areas, and enables route "
            "summarization at area boundaries (ABRs). "
            "Area 0 acts as the backbone; non-backbone areas connect via ABRs. "
            "All inter-area traffic transits Area 0."
        )

    if protocol == ProtocolChoice.MULTI_AREA_OSPF_BGP:
        as_list = ", ".join(str(a) for a in asns) if asns else "multiple"
        cloud_note = " and a cloud VPC boundary" if has_cloud else ""
        return (
            f"Multi-Area OSPF (internal) + eBGP (inter-domain) is recommended. "
            f"The plan spans autonomous systems {as_list}{cloud_note}, "
            "creating a routing boundary that requires an exterior routing protocol. "
            "eBGP provides policy-controlled route exchange between autonomous systems. "
            "OSPF handles intra-domain routing within each AS; "
            "BGP redistributes selected prefixes across AS boundaries. "
            "BGP path selection is policy-driven — convergence after a BGP session "
            "failure can take minutes depending on hold-down timers and path availability."
        )

    if protocol == ProtocolChoice.STATIC:
        return (
            "Static routing is specified. This is appropriate for simple topologies "
            "with a single default gateway, but does not scale and provides no "
            "automatic failover. Ensure static routes are carefully documented."
        )

    return f"Protocol: {protocol.value}."


def _build_area_justification(
    protocol: ProtocolChoice,
    ospf_areas: list[OspfAreaSpec],
    site_count: int,
    subnet_count: int,
) -> str:
    """Explain why single or multi-area OSPF is appropriate."""
    if protocol == ProtocolChoice.OSPF:
        return (
            "Single OSPF Area 0 is appropriate because all sites belong to one "
            f"autonomous system and the subnet count ({subnet_count}) is below the "
            f"{OSPF_SINGLE_AREA_SUBNET_THRESHOLD}-subnet threshold. "
            "A single area minimises configuration complexity; "
            "all routers maintain the full LSDB for the area."
        )

    if protocol in (ProtocolChoice.MULTI_AREA_OSPF, ProtocolChoice.MULTI_AREA_OSPF_BGP):
        area_count = len(ospf_areas)
        backbone_areas = [a for a in ospf_areas if a.area_id == 0]
        non_backbone = [a for a in ospf_areas if a.area_id != 0]
        return (
            f"{area_count} OSPF area{'s are' if area_count != 1 else ' is'} defined: "
            f"Area 0 (backbone) plus {len(non_backbone)} non-backbone area(s). "
            "Area boundaries (ABRs) limit LSA flooding and allow summarisation. "
            "Each non-backbone area's internal topology is hidden from other areas, "
            "reducing LSDB size on non-ABR routers. "
            "Area 0 must remain contiguous; all non-backbone areas must connect "
            "directly to Area 0 via ABRs or virtual links."
        )

    return ""


def _build_bgp_justification(
    protocol: ProtocolChoice,
    bgp_peers: list[BgpPeerSpec],
    asns: list[int],
    has_cloud: bool,
) -> str:
    """Explain why BGP is or is not applicable."""
    if protocol not in (ProtocolChoice.BGP, ProtocolChoice.MULTI_AREA_OSPF_BGP):
        return (
            "BGP is not applicable for this plan. "
            "All sites belong to a single autonomous system and no cloud routing "
            "boundary was detected. OSPF provides sufficient intra-domain routing."
        )

    ebgp_peers = [p for p in bgp_peers if p.peer_type == "eBGP"]
    ibgp_peers = [p for p in bgp_peers if p.peer_type == "iBGP"]
    as_list = ", ".join(str(a) for a in asns) if asns else "multiple"

    lines = [
        f"eBGP is justified because the plan spans autonomous systems ({as_list})"
        + (" including a cloud VPC" if has_cloud else "") + ". "
    ]

    if ebgp_peers:
        lines.append(
            f"{len(ebgp_peers)} eBGP peer session(s) are configured. "
            "eBGP controls which prefixes are advertised between ASes using "
            "route-maps and prefix-lists — avoid unrestricted redistribution. "
        )

    if ibgp_peers:
        lines.append(
            f"{len(ibgp_peers)} iBGP peer session(s) are also configured. "
            "iBGP requires full-mesh or route-reflector architecture within the AS. "
        )

    lines.append(
        "BGP route filtering must be configured to prevent advertising private "
        "prefixes externally. This planner does not verify BGP policy completeness."
    )

    return "".join(lines)


def _build_redundancy_notes(
    redundancy_mode: RedundancyMode,
    plan: dict,
) -> list[str]:
    """Build redundancy engineering notes from the plan."""
    notes: list[str] = []

    if redundancy_mode == RedundancyMode.RSTP:
        notes.append(
            "RSTP (IEEE 802.1w) is configured for Layer 2 loop prevention. "
            "Designate the core switch as the RSTP root (priority 4096) and a "
            "distribution switch as backup root (priority 8192). "
            "All other switches use the default priority (32768)."
        )
        notes.append(
            "PortFast should be enabled on access ports connecting end devices. "
            "BPDU Guard should be enabled on PortFast ports to prevent rogue switches."
        )

    elif redundancy_mode == RedundancyMode.DUAL_HOMED:
        notes.append(
            "Dual-homed connectivity provides active/standby path redundancy. "
            "Configure the primary path as active; the secondary path activates "
            "on primary path failure."
        )
        notes.append(
            "OSPF will detect link failure when the hello adjacency expires "
            "(typically 4 × hello interval = 40 s with default timers). "
            "Sub-second failover requires BFD (Bidirectional Forwarding Detection). "
            "Failover time is not guaranteed by this planner."
        )
        evpl = plan.get("evpl_connectivity", False)
        if evpl:
            notes.append(
                "EVPL (Ethernet Virtual Private Line) connectivity is indicated. "
                "EVPL provides a point-to-point Ethernet service over the carrier network. "
                "Redundant EVPL circuits require carrier-side provisioning. "
                "Confirm SLA terms for failover time with the carrier."
            )

    elif redundancy_mode == RedundancyMode.IPSEC_FAILOVER:
        notes.append(
            "IPsec VPN failover is the redundancy mechanism for WAN links. "
            "Configure Dead Peer Detection (DPD) to detect tunnel failures. "
            "Floating static routes or OSPF over GRE/IPsec can restore connectivity "
            "automatically after tunnel re-establishment."
        )
        notes.append(
            "IPsec tunnel re-establishment time depends on IKE negotiation, "
            "DPD intervals, and network path recovery. "
            "This planner does not guarantee failover timing."
        )

    return notes


def _build_assumptions(
    protocol: ProtocolChoice,
    plan: dict,
    asns: list[int],
) -> list[str]:
    """Build explicit assumptions for this routing decision."""
    assumptions: list[str] = [
        "Router process IDs are assigned per-device by the configuration generator.",
        "IP addresses for routed interfaces are sourced from the VLSM allocator.",
    ]

    if protocol in (ProtocolChoice.OSPF, ProtocolChoice.MULTI_AREA_OSPF):
        assumptions.append(
            "OSPF router IDs are assumed to be the highest IP address on each router "
            "or a dedicated loopback address — verify device-specific configuration."
        )
        assumptions.append(
            "OSPF network statements use 'network <prefix> <wildcard> area <id>' syntax "
            "for Cisco IOS. Verify area assignments match the allocated subnets."
        )

    if protocol in (ProtocolChoice.BGP, ProtocolChoice.MULTI_AREA_OSPF_BGP):
        assumptions.append(
            "BGP peer addresses must be reachable before adjacencies form. "
            "Ensure IGP (OSPF) covers loopback/peer addresses before enabling BGP."
        )
        assumptions.append(
            "BGP route filtering (prefix-lists, route-maps) is required before deployment. "
            "Templates in the configuration generator use placeholder filters."
        )

    qos = plan.get("qos_required", False)
    if qos:
        assumptions.append(
            "QoS classification and queuing configuration depends on traffic profiles "
            "that are not fully specified in this plan. Templates use DSCP-based marking."
        )

    ipsec = plan.get("ipsec_vpn_required", False)
    if ipsec:
        assumptions.append(
            "IPsec peer addresses, pre-shared keys, and crypto parameters are "
            "deployment-specific. The configuration generator uses placeholder values."
        )
        assumptions.append(
            "IKE Phase 1 and Phase 2 parameters must be agreed with all VPN peers "
            "before deployment."
        )

    return assumptions


def _build_warnings(plan: dict, protocol: ProtocolChoice) -> list[str]:
    """Build non-blocking engineering warnings."""
    warnings: list[str] = []

    latency = plan.get("latency_target_ms")
    if latency is not None:
        warnings.append(
            f"Latency target of {latency} ms: this target cannot be guaranteed by "
            "routing protocol selection alone. Physical propagation, carrier queuing, "
            "and CPE processing all contribute to end-to-end latency. "
            "Validate against carrier SLA and measured values after deployment."
        )

    route_summ = plan.get("route_summarization", False)
    if route_summ and protocol in (ProtocolChoice.OSPF,):
        warnings.append(
            "Route summarization is requested but single-area OSPF has no ABR "
            "for summarization. Consider multi-area OSPF or summarize at redistribution points."
        )

    ipsec = plan.get("ipsec_vpn_required", False)
    if ipsec and protocol == ProtocolChoice.OSPF:
        warnings.append(
            "IPsec VPN is required but single-area OSPF is selected. "
            "For WAN VPN scenarios, multi-area OSPF over GRE/IPsec tunnels or "
            "BGP is typically more appropriate."
        )

    return warnings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def decide_routing(plan: dict, subnet_count: Optional[int] = None) -> RoutingDecision:
    """
    Make a deterministic routing protocol decision for the given network plan.

    Parameters
    ----------
    plan : dict
        A validated network plan dict (from get_preset() or user input).
    subnet_count : int | None
        Number of subnets to consider.  If None, derived from
        len(plan['subnet_requests']).  Pass the actual VLSM result count
        for the most accurate decision.

    Returns
    -------
    RoutingDecision
        Fully structured, explainable routing decision.
    """
    if subnet_count is None:
        subnet_count = len(plan.get("subnet_requests", []))

    sites       = plan.get("sites", [])
    site_count  = len(sites)
    asns        = _extract_asns(plan)
    has_cloud   = _has_cloud_site(plan)
    bgp_peers   = plan.get("bgp_peers", [])
    ospf_areas  = plan.get("ospf_areas", [])
    ipsec       = plan.get("ipsec_vpn_required", False)
    route_summ  = plan.get("route_summarization", False)
    qos         = plan.get("qos_required", False)
    stp_mode    = plan.get("stp_mode", "rstp")
    native_vlan = plan.get("native_vlan", 999)

    has_boundary = _has_routing_boundary(asns, has_cloud, bgp_peers)

    protocol = _choose_protocol(
        subnet_count=subnet_count,
        site_count=site_count,
        has_routing_boundary=has_boundary,
        ospf_areas=ospf_areas,
        ipsec_required=ipsec,
        route_summ=route_summ,
    )

    ospf_area_specs = _build_ospf_areas(plan, protocol)
    bgp_peer_specs  = _build_bgp_peers(plan, protocol)
    single_area     = (len(ospf_area_specs) <= 1)

    # Redundancy mode
    redundancy_str = plan.get("redundancy", "none")
    try:
        redundancy_mode = RedundancyMode(redundancy_str)
    except ValueError:
        redundancy_mode = RedundancyMode.NONE

    # Summary boundary description
    if route_summ and protocol in (ProtocolChoice.MULTI_AREA_OSPF, ProtocolChoice.MULTI_AREA_OSPF_BGP):
        summary_boundary = (
            "Summarization should occur at ABR routers (Area Border Routers) "
            "when advertising routes from non-backbone areas into Area 0. "
            "Each site's subnets should be aggregated into the smallest covering prefix "
            "that does not overlap with other areas."
        )
    elif route_summ:
        summary_boundary = (
            "Route summarization is requested. With the current protocol selection, "
            "summarization can occur at redistribution boundaries or the WAN edge."
        )
    else:
        summary_boundary = ""

    protocol_just  = _build_protocol_justification(protocol, subnet_count, site_count, asns, has_boundary, has_cloud)
    area_just      = _build_area_justification(protocol, ospf_area_specs, site_count, subnet_count)
    bgp_just       = _build_bgp_justification(protocol, bgp_peer_specs, asns, has_cloud)
    redundancy_notes = _build_redundancy_notes(redundancy_mode, plan)
    assumptions    = _build_assumptions(protocol, plan, asns)
    warnings       = _build_warnings(plan, protocol)

    return RoutingDecision(
        protocol=protocol,
        subnet_count=subnet_count,
        site_count=site_count,
        autonomous_systems=asns,
        has_routing_boundary=has_boundary,
        single_area_ospf=single_area,
        ospf_areas=ospf_area_specs,
        bgp_peers=bgp_peer_specs,
        route_summarization=route_summ,
        summary_boundary=summary_boundary,
        redundancy_mode=redundancy_mode,
        qos_required=qos,
        ipsec_vpn_required=ipsec,
        stp_mode=stp_mode,
        native_vlan=native_vlan,
        protocol_justification=protocol_just,
        area_justification=area_just,
        bgp_justification=bgp_just,
        redundancy_notes=redundancy_notes,
        assumptions=assumptions,
        warnings=warnings,
    )
