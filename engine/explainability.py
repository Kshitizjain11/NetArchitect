"""
engine/explainability.py
-------------------------
Contextual engineering explainability engine for NetArchitect.

Per Section 9 of PROJECT_SPEC.md:
For each major decision, display:
  1. Selected technology or result.
  2. Actual input values.
  3. Rule or threshold applied.
  4. Calculation or relevant standard.
  5. Technical reason.
  6. Warnings, assumptions and limitations.

The text is dynamically generated from real structured decision results,
never static text or LLM hallucinations. All calculations and validations
are deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from engine.media_engine import (
    MediaDecision,
    MediumType,
    evaluate_all_links,
    COPPER_MAX_M,
    MMF_MAX_M,
)
from engine.vlsm_allocator import VLSMResult, SubnetAllocation, allocate_from_plan
from engine.routing_engine import (
    RoutingDecision,
    ProtocolChoice,
    RedundancyMode,
    decide_routing,
    OSPF_SINGLE_AREA_SUBNET_THRESHOLD,
)
from engine.topology_engine import (
    TopologyPlan,
    DeviceSpec,
    plan_topology,
)


@dataclass
class DecisionJustification:
    """
    Structured 6-point justification for a single engineering decision.

    Guarantees conformance with Section 9 of PROJECT_SPEC.md:
      1. Selected technology or result
      2. Actual input values
      3. Rule or threshold applied
      4. Calculation or relevant standard
      5. Technical reason
      6. Warnings, assumptions, and limitations
    """
    category: str                    # "media", "vlsm", "routing", "topology", "qos", "security"
    subject: str                     # e.g. "Link: Core to Distribution", "Subnet: IT Admin"
    selected_result: str             # 1. Selected technology or result
    actual_inputs: dict[str, Any]    # 2. Actual input values
    rule_applied: str                # 3. Rule or threshold applied
    calculation_or_standard: str     # 4. Calculation or relevant standard
    technical_reason: str            # 5. Technical reason
    warnings_and_assumptions: list[str] = field(default_factory=list) # 6. Warnings, assumptions, limitations

    def format_markdown(self) -> str:
        """Render justification in clean GitHub Markdown format."""
        inputs_str = ", ".join(f"`{k}` = {v}" for k, v in self.actual_inputs.items())
        warnings_md = ""
        if self.warnings_and_assumptions:
            items = "\n".join(f"  - {w}" for w in self.warnings_and_assumptions)
            warnings_md = f"\n- **Warnings & Assumptions:**\n{items}"

        return (
            f"### {self.subject} ({self.category.upper()})\n"
            f"- **Selected Technology / Result:** {self.selected_result}\n"
            f"- **Actual Input Values:** {inputs_str}\n"
            f"- **Rule / Threshold Applied:** {self.rule_applied}\n"
            f"- **Calculation / Standard:** {self.calculation_or_standard}\n"
            f"- **Technical Reason:** {self.technical_reason}"
            f"{warnings_md}\n"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "subject": self.subject,
            "selected_result": self.selected_result,
            "actual_inputs": self.actual_inputs,
            "rule_applied": self.rule_applied,
            "calculation_or_standard": self.calculation_or_standard,
            "technical_reason": self.technical_reason,
            "warnings_and_assumptions": list(self.warnings_and_assumptions),
        }


@dataclass
class ExplainabilityReport:
    """
    Aggregated explainability report for a complete network scenario.
    """
    scenario_name: str
    media_justifications: list[DecisionJustification] = field(default_factory=list)
    vlsm_justifications: list[DecisionJustification] = field(default_factory=list)
    routing_justifications: list[DecisionJustification] = field(default_factory=list)
    topology_justifications: list[DecisionJustification] = field(default_factory=list)

    @property
    def all_justifications(self) -> list[DecisionJustification]:
        return (
            self.media_justifications
            + self.vlsm_justifications
            + self.routing_justifications
            + self.topology_justifications
        )

    def format_markdown(self) -> str:
        """Format the full report in structured Markdown."""
        lines = [
            f"# Engineering Justification Report: {self.scenario_name}\n",
            "This report documents the contextual engineering rationale for all deterministic recommendations, "
            "mapping directly to assignment requirements and IEEE / IETF standards.\n",
        ]

        if self.media_justifications:
            lines.append("## 1. Physical Media Decisions\n")
            for j in self.media_justifications:
                lines.append(j.format_markdown())

        if self.vlsm_justifications:
            lines.append("## 2. Addressing & VLSM Subnet Allocations\n")
            for j in self.vlsm_justifications:
                lines.append(j.format_markdown())

        if self.routing_justifications:
            lines.append("## 3. Routing Architecture Decisions\n")
            for j in self.routing_justifications:
                lines.append(j.format_markdown())

        if self.topology_justifications:
            lines.append("## 4. Layer 2, Security & Resilience Decisions\n")
            for j in self.topology_justifications:
                lines.append(j.format_markdown())

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section Justification Builders
# ---------------------------------------------------------------------------

def explain_media_decision(link_name: str, decision: MediaDecision) -> DecisionJustification:
    """Produce a 6-point justification for a physical media decision."""
    dist = decision.distance_m
    req = decision.requested_medium or "automatic (unspecified)"
    bw = f"{decision.bandwidth_gbps} Gbps" if decision.bandwidth_gbps is not None else "unspecified"

    inputs = {
        "distance_m": dist,
        "bandwidth": bw,
        "requested_medium": req,
    }

    if decision.is_virtual:
        return DecisionJustification(
            category="media",
            subject=f"Link '{link_name}'",
            selected_result="Virtual / Cloud Interconnect (No physical cabling)",
            actual_inputs=inputs,
            rule_applied="Distance = 0 m (Cloud/virtual link bypasses physical media engine)",
            calculation_or_standard="IETF RFC 7348 / Cloud Provider VPC Peering specifications",
            technical_reason="Zero physical distance indicates a logical intra-cloud or virtual gateway connection.",
            warnings_and_assumptions=list(decision.assumptions),
        )

    # Determine rule applied & standard
    if dist <= COPPER_MAX_M:
        rule = f"Distance ({dist:.0f} m) <= {COPPER_MAX_M:.0f} m limit for Cat6a copper"
        calc = f"Channel length: {dist:.0f} m <= 100 m total channel (90 m horizontal + 10 m patch) per IEEE 802.3an (10GBASE-T)"
        tech = (
            f"Cat6a UTP/STP copper is recommended because the {dist:.0f} m run falls within the 100 m structured cabling boundary. "
            f"Copper provides cost-effective 10 Gbps transmission using standard RJ-45 PHY interfaces without requiring optical transceivers."
        )
    elif dist <= MMF_MAX_M:
        rule = f"Distance ({dist:.0f} m) > {COPPER_MAX_M:.0f} m copper limit and <= {MMF_MAX_M:.0f} m OM4 multimode fiber threshold"
        calc = f"OM4 modal bandwidth: 4700 MHz*km at 850 nm; reach up to 400 m under IEEE 802.3ae 10GBASE-SR"
        tech = (
            f"OM4 laser-optimized multimode fiber with SFP+ SR optics (850 nm) was recommended because the link distance "
            f"({dist:.0f} m) exceeds copper's 100 m limit but is within OM4 reach. OM4 offers lower transceiver power and port cost than single-mode fiber."
        )
    else:
        dist_km = dist / 1000.0
        rule = f"Distance ({dist:.0f} m / {dist_km:.2f} km) > {MMF_MAX_M:.0f} m multimode fiber threshold"
        optics_type = "10GBASE-ER (1550 nm)" if dist > 10000 else "10GBASE-LR (1310 nm)"
        calc = f"Attenuation on OS2 fiber <= 0.4 dB/km at 1310 nm, <= 0.25 dB/km at 1550 nm; IEEE 802.3ae ({optics_type})"
        tech = (
            f"OS2 single-mode fiber was recommended because the link distance ({dist:.0f} m / {dist_km:.2f} km) exceeds the 400 m "
            f"multimode fiber recommendation boundary. Modal dispersion renders multimode unusable at this range, requiring single-mode core (9/125 um)."
        )

    warnings: list[str] = list(decision.assumptions)
    if decision.violation:
        warnings.append(f"VIOLATION: {decision.violation_message}")
    if decision.attenuation_warning:
        warnings.append(f"ATTENUATION NOTICE: {decision.attenuation_warning}")

    return DecisionJustification(
        category="media",
        subject=f"Link '{link_name}'",
        selected_result=f"{decision.cable_type} ({decision.transceiver})",
        actual_inputs=inputs,
        rule_applied=rule,
        calculation_or_standard=calc,
        technical_reason=tech,
        warnings_and_assumptions=warnings,
    )


def explain_vlsm_allocation(alloc: SubnetAllocation, root_prefix: str) -> DecisionJustification:
    """Produce a 6-point justification for an individual VLSM subnet allocation."""
    inputs = {
        "subnet_name": alloc.name,
        "requested_hosts": alloc.requested_hosts,
        "root_network": root_prefix,
    }

    if alloc.status == "exhaustion_error" or alloc.status == "exhausted":
        return DecisionJustification(
            category="vlsm",
            subject=f"Subnet '{alloc.name}'",
            selected_result="Address Space Exhaustion (Unallocated)",
            actual_inputs=inputs,
            rule_applied=f"Root prefix {root_prefix} exhausted before satisfying required block size",
            calculation_or_standard="VLSM Descending Allocation Algorithm",
            technical_reason=f"Insufficient unallocated contiguous host space in {root_prefix} to fit {alloc.requested_hosts} hosts.",
            warnings_and_assumptions=[alloc.status_detail or "Expand root network or reduce host reservations."],
        )

    # Prefix calculation details
    total_addrs = alloc.total_addresses
    usable_hosts = alloc.usable_hosts
    p_len = alloc.prefix_length

    rule = (
        f"Select smallest prefix /{p_len} such that usable capacity (2^(32 - {p_len}) - 2 = {usable_hosts}) >= "
        f"required hosts ({alloc.requested_hosts})"
    )
    calc = (
        f"Block: /{p_len} (Netmask {alloc.subnet_mask}, Wildcard {alloc.wildcard_mask}). "
        f"Total: {total_addrs} IPs, Usable: {usable_hosts} IPs [{alloc.first_host} to {alloc.last_host}], "
        f"Gateway: {alloc.gateway} (first usable IP = network + 1), Broadcast: {alloc.broadcast_address}"
    )

    efficiency = (alloc.requested_hosts / usable_hosts * 100.0) if usable_hosts > 0 else 0.0
    tech = (
        f"Allocated {alloc.prefix} ({usable_hosts} usable hosts) for '{alloc.name}' with {alloc.requested_hosts} requested hosts "
        f"(efficiency: {efficiency:.1f}%). Subnets are allocated in strictly descending host order to ensure natural binary alignment "
        f"and eliminate internal fragmentation within {root_prefix}."
    )

    warnings = []
    if alloc.is_special_prefix:
        warnings.append("Point-to-point /30 subnet reserves 2 host addresses, network, and broadcast address per RFC 791.")
    if efficiency < 50.0 and alloc.requested_hosts > 4:
        warnings.append(f"Subnet allocation efficiency is {efficiency:.1f}%; reserved headroom for future growth.")

    return DecisionJustification(
        category="vlsm",
        subject=f"Subnet '{alloc.name}'",
        selected_result=f"{alloc.prefix} (Netmask: {alloc.subnet_mask})",
        actual_inputs=inputs,
        rule_applied=rule,
        calculation_or_standard=calc,
        technical_reason=tech,
        warnings_and_assumptions=warnings,
    )


def explain_routing_architecture(decision: RoutingDecision) -> list[DecisionJustification]:
    """Produce 6-point justifications for routing protocol and topology decisions."""
    justifications: list[DecisionJustification] = []

    # 1. Routing protocol justification
    inputs = {
        "subnet_count": decision.subnet_count,
        "site_count": decision.site_count,
        "autonomous_systems": decision.autonomous_systems,
        "has_routing_boundary": decision.has_routing_boundary,
    }

    if decision.protocol == ProtocolChoice.OSPF:
        rule = (
            f"Single autonomous system (ASN {decision.autonomous_systems}) AND "
            f"subnet count ({decision.subnet_count}) < {OSPF_SINGLE_AREA_SUBNET_THRESHOLD} subnets"
        )
        calc = "Dijkstra Link-State SPF Algorithm (IETF RFC 2328 / OSPFv2)"
        tech = (
            f"Single-Area OSPF (Area 0) is recommended because the entire topology resides within a single "
            f"administrative domain and contains {decision.subnet_count} subnets (below the {OSPF_SINGLE_AREA_SUBNET_THRESHOLD}-subnet "
            f"threshold where SPF recalculation overhead and LSDB sizing warrant multi-area hierarchical segmentation)."
        )
    elif decision.protocol == ProtocolChoice.MULTI_AREA_OSPF:
        rule = (
            f"Single autonomous system with subnet count ({decision.subnet_count}) >= {OSPF_SINGLE_AREA_SUBNET_THRESHOLD} "
            f"OR multi-site geographic distribution requiring fault isolation"
        )
        calc = "OSPFv2 Multi-Area Hierarchy (Area 0 Backbone + Non-Backbone Stub/Standard Areas)"
        tech = (
            f"Multi-Area OSPF is selected to partition the {decision.subnet_count} subnets across {len(decision.ospf_areas)} areas. "
            f"This limits SPF calculation scope to individual areas, isolates link flapping via Type 3 Summary LSAs, "
            f"and enables clean inter-area route summarization on Area Border Routers (ABRs)."
        )
    elif decision.protocol == ProtocolChoice.BGP:
        rule = f"Multiple autonomous systems ({len(decision.autonomous_systems)} ASNs: {decision.autonomous_systems}) detected"
        calc = "Path-Vector Protocol (IETF RFC 4271 / BGP-4) with AS_PATH loop prevention"
        tech = (
            f"Exterior BGP (eBGP) is required across autonomous system boundaries to exchange policy-controlled prefixes "
            f"between AS {decision.autonomous_systems[0]} and external peer ASNs. BGP provides policy routing and administrative domain separation."
        )
    elif decision.protocol == ProtocolChoice.MULTI_AREA_OSPF_BGP:
        rule = (
            f"Multi-site enterprise with both internal scaling ({decision.subnet_count} subnets) and "
            f"external/cloud routing boundaries (ASNs: {decision.autonomous_systems})"
        )
        calc = "Hierarchical IGP (OSPF Multi-Area) + Exterior Policy BGP (eBGP per RFC 4271) at ASBR border"
        tech = (
            f"Hybrid OSPF Multi-Area + eBGP architecture is selected. OSPF handles high-speed internal convergence and "
            f"IGP reachability within the enterprise, while eBGP peers at Autonomous System Border Routers (ASBRs) to "
            f"safely peer with cloud VPCs or partner networks without injecting external routing churn into the internal IGP."
        )
    else:
        rule = "Static / Default Routing baseline"
        calc = "Static routing per RFC 1812"
        tech = "Static routing is adequate for single-uplink or minimal-subnet topologies."

    protocol_display_names = {
        ProtocolChoice.OSPF: "OSPF (Single Area 0)",
        ProtocolChoice.MULTI_AREA_OSPF: "Multi-Area OSPF",
        ProtocolChoice.BGP: "Exterior BGP (eBGP)",
        ProtocolChoice.MULTI_AREA_OSPF_BGP: "Multi-Area OSPF + eBGP",
        ProtocolChoice.STATIC: "Static Routing",
    }
    selected_proto = protocol_display_names.get(decision.protocol, decision.protocol.value)

    justifications.append(DecisionJustification(
        category="routing",
        subject="Routing Protocol Architecture",
        selected_result=selected_proto,
        actual_inputs=inputs,
        rule_applied=rule,
        calculation_or_standard=calc,
        technical_reason=tech,
        warnings_and_assumptions=list(decision.assumptions) + list(decision.warnings),
    ))

    # 2. Area structure justification if OSPF is used
    if decision.ospf_areas:
        area_ids = [a.area_id for a in decision.ospf_areas]
        area_inputs = {
            "configured_areas": area_ids,
            "single_area_mode": decision.single_area_ospf,
        }
        area_rule = "All non-backbone areas must connect directly to Area 0 (Backbone) per RFC 2328 §3.1"
        area_calc = f"{len(decision.ospf_areas)} OSPF areas defined: " + ", ".join(f"Area {a.area_id} ({a.area_type})" for a in decision.ospf_areas)
        area_tech = (
            f"Area 0 forms the core transit backbone. "
            + (
                "All subnets participate in Area 0 to optimize convergence and simplify operations."
                if decision.single_area_ospf
                else "Non-zero areas partition site-specific Link-State Databases, with ABRs performing LSA filtering and summary route generation."
            )
        )
        justifications.append(DecisionJustification(
            category="routing",
            subject="OSPF Hierarchical Area Topology",
            selected_result=f"{'Single Area (Area 0)' if decision.single_area_ospf else f'Multi-Area ({len(decision.ospf_areas)} areas)'}",
            actual_inputs=area_inputs,
            rule_applied=area_rule,
            calculation_or_standard=area_calc,
            technical_reason=area_tech,
            warnings_and_assumptions=[decision.area_justification],
        ))

    return justifications


def explain_topology_and_security(plan: TopologyPlan) -> list[DecisionJustification]:
    """Produce 6-point justifications for Spanning Tree, VLANs, QoS, and IPsec VPN."""
    justifications: list[DecisionJustification] = []

    # 1. Spanning Tree Protocol (STP)
    root_devices = [d for d in plan.devices if d.stp_priority == 4096]
    backup_devices = [d for d in plan.devices if d.stp_priority == 8192]
    stp_inputs = {
        "stp_mode": plan.stp_mode,
        "root_bridge": [d.hostname for d in root_devices],
        "backup_root": [d.hostname for d in backup_devices],
    }
    stp_rule = "Deterministically assign Bridge Priority 4096 to primary Core/Distribution switch, 8192 to secondary"
    stp_calc = "IEEE 802.1w Rapid Spanning Tree Protocol (RSTP) — 4096 priority increment per 802.1t"
    stp_tech = (
        f"Rapid Spanning Tree Protocol ({plan.stp_mode.upper()}) converges in < 1 second using direct proposal/agreement handshakes. "
        f"Explicit priority 4096 on {', '.join(d.hostname for d in root_devices) or 'Core'} guarantees root bridge placement at the network "
        f"center, preventing suboptimal traffic tromboning or bridge takeover by rogue access switches."
    )
    justifications.append(DecisionJustification(
        category="topology",
        subject="Spanning Tree (STP) Root Placement",
        selected_result=f"{plan.stp_mode.upper()} (Root Priority: 4096, Backup: 8192)",
        actual_inputs=stp_inputs,
        rule_applied=stp_rule,
        calculation_or_standard=stp_calc,
        technical_reason=stp_tech,
        warnings_and_assumptions=["Ensure BPDU Guard and PortFast are enabled on all edge access ports to prevent topology recalculation."],
    ))

    # 2. VLAN & Trunking Security
    vlan_inputs = {
        "vlan_count": len(plan.vlans),
        "native_vlan": plan.native_vlan,
        "vlans": [v.vlan_id for v in plan.vlans],
    }
    vlan_rule = "IEEE 802.1Q encapsulation with explicit allowed VLAN pruning; dedicated unused native VLAN"
    vlan_calc = f"VLAN ID range: {min(v.vlan_id for v in plan.vlans) if plan.vlans else 1}..{max(v.vlan_id for v in plan.vlans) if plan.vlans else 1}; Native VLAN: {plan.native_vlan}"
    vlan_tech = (
        f"Trunk links explicitly permit only designated active VLANs rather than the default 'all', eliminating unnecessary "
        f"broadcast flooding. Native VLAN is assigned to an isolated ID ({plan.native_vlan}) rather than default VLAN 1 "
        f"to mitigate 802.1Q double-tagging VLAN hopping attacks."
    )
    justifications.append(DecisionJustification(
        category="topology",
        subject="802.1Q VLAN Trunking & Native VLAN Isolation",
        selected_result=f"Pruned Trunks with Dedicated Native VLAN {plan.native_vlan}",
        actual_inputs=vlan_inputs,
        rule_applied=vlan_rule,
        calculation_or_standard=vlan_calc,
        technical_reason=vlan_tech,
        warnings_and_assumptions=["Never assign access ports to the native VLAN ID."],
    ))

    # 3. QoS Policy (Metro MAN profile)
    if plan.qos_policies:
        for qos in plan.qos_policies:
            qos_inputs = {
                "policy_name": qos.policy_name,
                "classes": [c.get("name") for c in qos.class_maps],
            }
            qos_rule = "Differentiated Services (DiffServ) per RFC 4594 for multi-service Metro EVPL links"
            qos_calc = "Voice: DSCP EF (46) priority queue; Video: AF41 (DSCP 34); Critical: AF21 (DSCP 18); Default: Fair-queue"
            qos_tech = (
                f"Policy '{qos.policy_name}' guarantees strict-priority low-latency queuing for real-time voice and video "
                f"traffic over shared metropolitan links, reserving minimum bandwidth guarantees for mission-critical ERP data "
                f"to prevent buffer bloat and queue exhaustion during peak congestion."
            )
            justifications.append(DecisionJustification(
                category="qos",
                subject=f"Quality of Service (QoS) Policy '{qos.policy_name}'",
                selected_result="Class-Based Weighted Fair Queuing (CBWFQ) + Low Latency Queuing (LLQ)",
                actual_inputs=qos_inputs,
                rule_applied=qos_rule,
                calculation_or_standard=qos_calc,
                technical_reason=qos_tech,
                warnings_and_assumptions=[qos.description],
            ))

    # 4. IPsec VPN Security (Global WAN profile)
    if plan.ipsec_tunnels:
        for tunnel in plan.ipsec_tunnels:
            vpn_inputs = {
                "tunnel_id": tunnel.tunnel_id,
                "local_site": tunnel.local_site,
                "remote_site": tunnel.remote_site,
                "encryption": tunnel.encryption,
                "hash": tunnel.authentication,
                "dh_group": tunnel.dh_group,
            }
            vpn_rule = "IETF RFC 7296 (IKEv2) / RFC 4301 (IPsec) with modern cryptographic suites"
            enc_display = tunnel.encryption.upper().replace("AES ", "AES-")
            vpn_calc = f"{enc_display} + {tunnel.authentication.upper()} + DH Group {tunnel.dh_group} (2048-bit MODP)"
            vpn_tech = (
                f"Site-to-site IPsec tunnel {tunnel.tunnel_id} between {tunnel.local_site} and {tunnel.remote_site} "
                f"secures WAN interconnects across public transit. AES-256 in CBC/GCM mode provides confidentiality, "
                f"SHA-256 HMAC guarantees data integrity, and Diffie-Hellman Group {tunnel.dh_group} delivers forward secrecy. "
                f"Dead Peer Detection (DPD interval {tunnel.dpd_interval}s) ensures fast failover upon tunnel termination."
            )
            justifications.append(DecisionJustification(
                category="security",
                subject=f"IPsec VPN Tunnel {tunnel.tunnel_id} ({tunnel.local_site} -> {tunnel.remote_site})",
                selected_result=f"IPsec Site-to-Site Tunnel ({tunnel.encryption} / {tunnel.authentication})",
                actual_inputs=vpn_inputs,
                rule_applied=vpn_rule,
                calculation_or_standard=vpn_calc,
                technical_reason=vpn_tech,
                warnings_and_assumptions=[
                    "Pre-shared keys and peer public IPs are structured placeholders and MUST be configured prior to live deployment.",
                    f"Dead Peer Detection configured for {tunnel.dpd_interval}s keepalive with {tunnel.dpd_retry} retries.",
                ],
            ))

    return justifications


# ---------------------------------------------------------------------------
# Master Report Generation Entrypoint
# ---------------------------------------------------------------------------

def generate_explainability_report(
    plan: dict,
    media_decisions: Optional[list[MediaDecision]] = None,
    vlsm_result: Optional[VLSMResult] = None,
    routing_decision: Optional[RoutingDecision] = None,
    topology_plan: Optional[TopologyPlan] = None,
) -> ExplainabilityReport:
    """
    Generate a complete, structured ExplainabilityReport for the supplied plan.

    If intermediate decision models are not provided, this function computes them
    deterministically from the raw plan dict.
    """
    raw_scenario = plan.get("scenario", "Custom Scenario")
    scenario_map = {
        "campus_lan": "Campus LAN",
        "metro_man": "Metro MAN",
        "global_wan": "Global WAN",
    }
    scenario_name = scenario_map.get(raw_scenario, raw_scenario)

    # 1. Physical media decisions
    if media_decisions is None:
        media_decisions = evaluate_all_links(plan.get("links", []))

    media_justifications: list[DecisionJustification] = []
    links = plan.get("links", [])
    for idx, dec_item in enumerate(media_decisions):
        actual_dec = dec_item["media_decision"] if isinstance(dec_item, dict) and "media_decision" in dec_item else dec_item
        link_name = links[idx].get("name", f"Link {idx+1}") if idx < len(links) else f"Link {idx+1}"
        media_justifications.append(explain_media_decision(link_name, actual_dec))

    # 2. VLSM Subnet Allocations
    if vlsm_result is None and "root_network" in plan and "subnet_requests" in plan:
        vlsm_result = allocate_from_plan(plan)

    vlsm_justifications: list[DecisionJustification] = []
    root_net = plan.get("root_network", "unspecified")
    if vlsm_result is not None:
        for alloc in vlsm_result.allocations:
            vlsm_justifications.append(explain_vlsm_allocation(alloc, root_net))

    # 3. Routing Architecture
    if routing_decision is None:
        subnet_count = len(vlsm_result.allocations) if vlsm_result else len(plan.get("subnet_requests", []))
        routing_decision = decide_routing(plan, subnet_count=subnet_count)

    routing_justifications = explain_routing_architecture(routing_decision)

    # 4. Topology, VLANs, QoS, Security
    if topology_plan is None:
        topology_plan = plan_topology(plan, routing_decision, vlsm_result)

    topology_justifications = explain_topology_and_security(topology_plan)

    return ExplainabilityReport(
        scenario_name=scenario_name,
        media_justifications=media_justifications,
        vlsm_justifications=vlsm_justifications,
        routing_justifications=routing_justifications,
        topology_justifications=topology_justifications,
    )
