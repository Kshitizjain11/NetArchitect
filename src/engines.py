"""Deterministic L1-L3 rule engines for NetArchitect."""
import ipaddress
import math
from typing import List, Optional, Union

from src.models import (
    AddressExhaustionError,
    L1Decision,
    PhysicalDistanceViolationError,
    RoutingDecision,
    SubnetAllocation,
    SubnetRequest,
)


class L1MediaEngine:
    """Rule engine for physical layer (L1) transmission media selection and justification."""

    COPPER_LIMIT_M = 100.0
    MMF_LIMIT_M = 400.0

    @classmethod
    def evaluate(cls, distance_m: float, requested_media: Optional[str] = None) -> L1Decision:
        """
        Evaluate link distance and media constraints using IEEE 802.3 standards.

        Args:
            distance_m: Distance in meters between endpoints.
            requested_media: Optional requested media type (e.g., 'copper', 'fiber').

        Returns:
            L1Decision with selected media specification and engineering rationale.

        Raises:
            PhysicalDistanceViolationError: When requested copper media exceeds 100m.
        """
        if requested_media:
            normalized_req = requested_media.strip().lower()
            if normalized_req in ("copper", "cat6", "cat6a", "utp", "stp", "10gbase-t") and distance_m > cls.COPPER_LIMIT_M:
                raise PhysicalDistanceViolationError(
                    f"Physical Distance Violation: Requested copper media ({requested_media}) exceeds "
                    f"IEEE 802.3an 100m physical link specification (link distance: {distance_m:.1f}m). "
                    "Severe high-frequency attenuation, insertion loss, and near-end crosstalk (NEXT) "
                    "will cause complete link failure or massive packet drop."
                )

        if distance_m <= cls.COPPER_LIMIT_M:
            media = "Cat6a (10GBASE-T)"
            std = "IEEE 802.3an (10GBASE-T)"
            rationale = (
                f"Selected {media} for {distance_m:.1f}m link. "
                "Complies with IEEE 802.3an standards for 10 Gigabit Ethernet over balanced 4-pair "
                "shielded/unshielded twisted pair cabling up to the 100-meter channel attenuation limit. "
                "Provides cost-effective, standard RJ-45 interconnectivity with minimal transceiver overhead."
            )
        elif distance_m <= cls.MMF_LIMIT_M:
            media = "OM4 MMF (10GBASE-SR)"
            std = "IEEE 802.3ae (10GBASE-SR) / TIA-492AAAD"
            rationale = (
                f"Selected {media} for {distance_m:.1f}m link. "
                f"Link distance exceeds IEEE 802.3an copper threshold ({cls.COPPER_LIMIT_M:.0f}m). "
                "Laser-optimized 50/125 µm multi-mode fiber (OM4) operating at 850nm VCSEL wavelength "
                "safely supports 10 Gbps transmission up to 400m before differential modal dispersion (DMD) "
                "induces bit error rate (BER) penalties."
            )
        else:
            media = "OS2 SMF (10GBASE-LR/ER)"
            std = "IEEE 802.3ae (10GBASE-LR/ER) / ITU-T G.652.D"
            km = distance_m / 1000.0
            rationale = (
                f"Selected {media} for {distance_m:.1f}m ({km:.2f}km) link. "
                f"Distance exceeds the 400m modal dispersion threshold of OM4 multi-mode fiber. "
                "Zero-water-peak OS2 Single-Mode Fiber (9/125 µm) operating at 1310nm/1550nm wavelength "
                "eliminates modal dispersion and provides the necessary optical link power budget "
                "for long-haul metropolitan or wide-area connectivity."
            )

        return L1Decision(
            selected_media=media,
            standard_reference=std,
            rationale=rationale,
            distance_m=distance_m,
            requested_media=requested_media,
        )


class VLSMAllocator:
    """Deterministic Variable Length Subnet Mask (VLSM) allocator using strict bitwise logic."""

    @staticmethod
    def calculate_block_size(host_count: int) -> int:
        """
        Compute required power-of-two block size for H usable hosts:
        block_size = 2^(ceil(log2(H + 2)))
        Accounting for network ID and broadcast address.
        """
        if host_count < 1:
            raise ValueError(f"Host count must be positive integer, got: {host_count}")
        needed = host_count + 2
        # Minimum block size for IPv4 subnetting with network and broadcast is 4 (/30)
        return 1 << max(2, (needed - 1).bit_length())

    @classmethod
    def allocate(
        cls,
        root_prefix: str,
        host_requests: List[Union[int, SubnetRequest]],
        vlan_start: int = 10,
        vlan_step: int = 10,
    ) -> List[SubnetAllocation]:
        """
        Deterministically allocate contiguous, non-overlapping subnets using VLSM.

        Args:
            root_prefix: Base CIDR network (e.g. '10.10.0.0/16').
            host_requests: List of host count integers or SubnetRequest objects.
            vlan_start: Starting VLAN ID for auto-numbering.
            vlan_step: Incremental step for VLAN IDs.

        Returns:
            List of SubnetAllocation objects sorted by block size descending.

        Raises:
            AddressExhaustionError: If required space exceeds the root prefix.
            ValueError: If root_prefix is invalid.
        """
        try:
            root_net = ipaddress.IPv4Network(root_prefix, strict=True)
        except Exception as exc:
            raise ValueError(f"Invalid root prefix '{root_prefix}': {exc}") from exc

        # Normalize requests into SubnetRequest instances
        normalized_requests: List[SubnetRequest] = []
        for idx, req in enumerate(host_requests):
            if isinstance(req, int):
                normalized_requests.append(
                    SubnetRequest(
                        name=f"Subnet_{idx + 1}",
                        hosts=req,
                        vlan_id=None,
                    )
                )
            elif isinstance(req, SubnetRequest):
                normalized_requests.append(req)
            elif isinstance(req, dict):
                normalized_requests.append(
                    SubnetRequest(
                        name=req.get("name", f"Subnet_{idx + 1}"),
                        hosts=req["hosts"],
                        vlan_id=req.get("vlan_id"),
                    )
                )
            else:
                raise TypeError(f"Unsupported request type: {type(req)}")

        # Mandatory VLSM Rule: Sort by required host count descending
        sorted_requests = sorted(normalized_requests, key=lambda r: r.hosts, reverse=True)

        allocations: List[SubnetAllocation] = []
        current_ip_int = int(root_net.network_address)
        max_ip_int = int(root_net.broadcast_address) + 1  # non-inclusive upper bound
        assigned_vlan = vlan_start

        for req in sorted_requests:
            block_size = cls.calculate_block_size(req.hosts)
            prefix_len = 32 - int(math.log2(block_size))

            # Ensure bitwise boundary alignment for CIDR block
            if current_ip_int % block_size != 0:
                current_ip_int = ((current_ip_int + block_size - 1) // block_size) * block_size

            # Check capacity exhaustion
            if current_ip_int + block_size > max_ip_int:
                total_requested_hosts = sum(r.hosts for r in sorted_requests)
                raise AddressExhaustionError(
                    f"Address Exhaustion: Allocation for request '{req.name}' ({req.hosts} hosts) "
                    f"requires block size {block_size} (/{prefix_len}). Offset 0x{current_ip_int:X} + {block_size} "
                    f"exceeds root prefix boundary '{root_prefix}' (max 0x{max_ip_int:X}). "
                    f"Total hosts requested: {total_requested_hosts}, Available in root: {root_net.num_addresses - 2}."
                )

            # Build IPv4Network representation
            net_obj = ipaddress.IPv4Network((current_ip_int, prefix_len))
            netmask_str = str(net_obj.netmask)
            wildcard_str = str(net_obj.hostmask)
            first_gateway = str(net_obj.network_address + 1)
            last_host = str(net_obj.broadcast_address - 1)
            broadcast_str = str(net_obj.broadcast_address)
            usable_hosts = block_size - 2
            efficiency = round(req.hosts / usable_hosts, 4)

            vlan_id = req.vlan_id if req.vlan_id is not None else assigned_vlan
            if req.vlan_id is None:
                assigned_vlan += vlan_step

            allocations.append(
                SubnetAllocation(
                    name=req.name,
                    vlan_id=vlan_id,
                    requested_hosts=req.hosts,
                    allocated_size=block_size,
                    usable_hosts=usable_hosts,
                    network_address=str(net_obj.network_address),
                    prefix_len=prefix_len,
                    netmask=netmask_str,
                    wildcard_mask=wildcard_str,
                    first_usable_gateway=first_gateway,
                    last_usable_host=last_host,
                    broadcast_address=broadcast_str,
                    utilization_efficiency=efficiency,
                )
            )

            # Advance current pointer past the allocated block
            current_ip_int += block_size

        return allocations


class RoutingEngine:
    """Rule engine for dynamic routing protocol selection and architectural justification."""

    SUBNET_THRESHOLD = 50

    @classmethod
    def evaluate(
        cls,
        subnet_count: int,
        single_as: bool = True,
        multi_site_or_cloud: bool = False,
    ) -> RoutingDecision:
        """
        Select routing architecture based on topology scale, administrative boundaries, and cloud reach.

        Args:
            subnet_count: Number of subnets to be routed.
            single_as: True if entirely within a single Autonomous System.
            multi_site_or_cloud: True if interconnecting multiple sites, data centers, or cloud VPCs.

        Returns:
            RoutingDecision containing selected protocol, topology scope, and detailed justification.
        """
        is_complex = (not single_as) or multi_site_or_cloud or (subnet_count >= cls.SUBNET_THRESHOLD)

        if not is_complex:
            protocol = "Single-Area OSPFv2 (Area 0)"
            scope = "Enterprise Campus Interior Gateway (IGP)"
            rationale = (
                f"Selected {protocol} for topology of {subnet_count} subnets within a single AS. "
                "Single-Area OSPF executes Dijkstra's Shortest Path First (SPF) algorithm natively across "
                "all nodes in Backbone Area 0. With fewer than 50 subnets, link-state database (LSDB) flooding "
                "overhead is negligible, eliminating the need for inter-area route summarization (ABRs) "
                "and providing sub-second link-state convergence with minimal router memory footprint."
            )
        else:
            protocol = "Hierarchical Multi-Area OSPF + eBGP"
            scope = "Multi-Site Metro / Global WAN Hybrid Core"
            reasons = []
            if multi_site_or_cloud:
                reasons.append("multi-site/cloud boundary interconnection")
            if not single_as:
                reasons.append("multi-AS administrative segregation")
            if subnet_count >= cls.SUBNET_THRESHOLD:
                reasons.append(f"subnet scale ({subnet_count} >= {cls.SUBNET_THRESHOLD})")

            trigger_str = ", ".join(reasons)
            rationale = (
                f"Selected {protocol} triggered by: {trigger_str}. "
                "Hierarchical OSPF segments the topology into Backbone Area 0 and edge stub/totally-stubby areas "
                "to contain Type-1 and Type-2 LSA flooding, localizing SPF recalculations during link flaps. "
                "External Border Gateway Protocol (eBGP) provides policy-driven inter-domain routing, "
                "AS-path loop prevention, and scalable peering across WAN transport and cloud VPC gateways."
            )

        return RoutingDecision(
            selected_protocol=protocol,
            topology_scope=scope,
            rationale=rationale,
            subnet_count=subnet_count,
            is_multi_as_or_cloud=is_complex,
        )
