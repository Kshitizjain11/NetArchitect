"""Comprehensive automated test suite for NetArchitect."""
import ipaddress
import pytest

from src.engines import L1MediaEngine, VLSMAllocator, RoutingEngine
from src.models import (
    AddressExhaustionError,
    PhysicalDistanceViolationError,
    SubnetRequest,
)
from src.presets import PRESETS, get_preset
from src.config_gen import CiscoConfigGenerator


# ==============================================================================
# 1. Physical Layer (L1) Distance Violation & Boundary Tests
# ==============================================================================

class TestL1MediaEngine:
    """Test suite for physical transmission media selection and IEEE distance limits."""

    def test_copper_distance_violation_error(self):
        """Verify PhysicalDistanceViolationError is raised when copper exceeds 100m."""
        # Exact boundary + 1m
        with pytest.raises(PhysicalDistanceViolationError) as exc_info:
            L1MediaEngine.evaluate(distance_m=101.0, requested_media="copper")
        assert "exceeds IEEE 802.3an 100m physical link specification" in str(exc_info.value)

        # 250m long run
        with pytest.raises(PhysicalDistanceViolationError) as exc_info_250:
            L1MediaEngine.evaluate(distance_m=250.0, requested_media="Cat6a")
        assert "exceeds IEEE 802.3an 100m" in str(exc_info_250.value)

    def test_copper_within_100m_succeeds(self):
        """Verify copper requests at or under 100m succeed without error."""
        decision_100 = L1MediaEngine.evaluate(distance_m=100.0, requested_media="copper")
        assert decision_100.selected_media == "Cat6a (10GBASE-T)"

        decision_50 = L1MediaEngine.evaluate(distance_m=50.0, requested_media="cat6a")
        assert decision_50.selected_media == "Cat6a (10GBASE-T)"

    @pytest.mark.parametrize(
        "distance_m, expected_media, expected_std",
        [
            (1.0, "Cat6a (10GBASE-T)", "IEEE 802.3an"),
            (100.0, "Cat6a (10GBASE-T)", "IEEE 802.3an"),
            (100.1, "OM4 MMF (10GBASE-SR)", "IEEE 802.3ae"),
            (101.0, "OM4 MMF (10GBASE-SR)", "IEEE 802.3ae"),
            (300.0, "OM4 MMF (10GBASE-SR)", "IEEE 802.3ae"),
            (400.0, "OM4 MMF (10GBASE-SR)", "IEEE 802.3ae"),
            (400.1, "OS2 SMF (10GBASE-LR/ER)", "IEEE 802.3ae"),
            (401.0, "OS2 SMF (10GBASE-LR/ER)", "IEEE 802.3ae"),
            (22000.0, "OS2 SMF (10GBASE-LR/ER)", "IEEE 802.3ae"),
            (50000.0, "OS2 SMF (10GBASE-LR/ER)", "ITU-T G.652.D"),
        ],
    )
    def test_media_boundary_transitions(self, distance_m, expected_media, expected_std):
        """Verify precise boundary transition across copper (100m), MMF (400m), and SMF (>400m)."""
        decision = L1MediaEngine.evaluate(distance_m=distance_m)
        assert decision.selected_media == expected_media
        assert expected_std in decision.standard_reference


# ==============================================================================
# 2. L3 VLSM Bitwise Allocator Tests
# ==============================================================================

class TestVLSMAllocator:
    """Test suite for deterministic VLSM allocation, boundary alignment, and zero overlap."""

    def test_zero_subnet_overlap_unsorted_input(self):
        """
        Verify that an arbitrarily unsorted host request array produces strictly contiguous,
        non-overlapping subnet blocks inside the root prefix.
        """
        root_prefix = "10.0.0.0/16"
        # Highly shuffled host demands
        unsorted_requests = [50, 1000, 2, 250, 14, 500, 6, 120]

        allocations = VLSMAllocator.allocate(root_prefix, unsorted_requests)

        # 1. Confirm allocation count matches input request count
        assert len(allocations) == len(unsorted_requests)

        # 2. Convert allocations to ipaddress objects
        net_objects = [ipaddress.IPv4Network(a.cidr) for a in allocations]
        root_net = ipaddress.IPv4Network(root_prefix)

        # 3. Confirm every allocated network is a valid subnet of root_prefix
        for net in net_objects:
            assert net.subnet_of(root_net)

        # 4. Pairwise disjointness assertion: NO two subnets may overlap
        for i in range(len(net_objects)):
            for j in range(i + 1, len(net_objects)):
                assert not net_objects[i].overlaps(net_objects[j]), (
                    f"Subnet overlap detected between {net_objects[i]} and {net_objects[j]}!"
                )

        # 5. Verify descending sort order invariant
        for i in range(len(allocations) - 1):
            assert allocations[i].allocated_size >= allocations[i + 1].allocated_size

    @pytest.mark.parametrize(
        "host_count, expected_prefix, expected_netmask, expected_wildcard",
        [
            (100, 25, "255.255.255.128", "0.0.0.127"),   # Edge case /25 (needed: 102 -> block 128)
            (5, 29, "255.255.255.248", "0.0.0.7"),       # Edge case /29 (needed: 7 -> block 8)
            (2, 30, "255.255.255.252", "0.0.0.3"),       # Edge case /30 (needed: 4 -> block 4, p2p)
            (1, 30, "255.255.255.252", "0.0.0.3"),       # 1 host still requires /30
            (250, 24, "255.255.255.0", "0.0.0.255"),     # Standard /24
            (500, 23, "255.255.254.0", "0.0.1.255"),     # Standard /23
            (1000, 22, "255.255.252.0", "0.0.3.255"),    # Standard /22
        ],
    )
    def test_exact_wildcard_and_netmask_calculations(
        self, host_count, expected_prefix, expected_netmask, expected_wildcard
    ):
        """Verify exact bitwise inversion of netmask into wildcard mask for OSPF."""
        allocations = VLSMAllocator.allocate("192.168.0.0/16", [host_count])
        alloc = allocations[0]

        assert alloc.prefix_len == expected_prefix
        assert alloc.netmask == expected_netmask
        assert alloc.wildcard_mask == expected_wildcard

        # Verify bitwise inverse relation mathematically
        netmask_int = int(ipaddress.IPv4Address(alloc.netmask))
        wildcard_int = int(ipaddress.IPv4Address(alloc.wildcard_mask))
        assert (netmask_int ^ wildcard_int) == 0xFFFFFFFF
        assert (netmask_int & wildcard_int) == 0

    def test_address_exhaustion_error(self):
        """Verify AddressExhaustionError is raised when host requests exceed root CIDR capacity."""
        # /24 has 254 usable addresses. Requesting 200 + 100 requires block 256 + block 128 = 384 addresses
        with pytest.raises(AddressExhaustionError) as exc_info:
            VLSMAllocator.allocate("192.168.1.0/24", [200, 100])
        assert "Address Exhaustion" in str(exc_info.value)
        assert "exceeds root prefix boundary" in str(exc_info.value)

        # Single request exceeding total space
        with pytest.raises(AddressExhaustionError):
            VLSMAllocator.allocate("10.0.0.0/28", [30])

    def test_gateway_and_usable_range(self):
        """Verify first gateway is .1, last host is broadcast - 1."""
        allocations = VLSMAllocator.allocate("172.16.0.0/24", [50])
        alloc = allocations[0]
        assert alloc.network_address == "172.16.0.0"
        assert alloc.first_usable_gateway == "172.16.0.1"
        assert alloc.last_usable_host == "172.16.0.62"
        assert alloc.broadcast_address == "172.16.0.63"


# ==============================================================================
# 3. L3 Routing Engine Tests
# ==============================================================================

class TestRoutingEngine:
    """Test suite for routing protocol decision matrix."""

    def test_single_area_ospf_selection(self):
        """Verify single AS with < 50 subnets selects Single-Area OSPFv2."""
        decision = RoutingEngine.evaluate(subnet_count=10, single_as=True, multi_site_or_cloud=False)
        assert "Single-Area OSPFv2" in decision.selected_protocol
        assert not decision.is_multi_as_or_cloud
        assert "Dijkstra" in decision.rationale

    def test_multi_area_ospf_bgp_selection_triggers(self):
        """Verify multi-site, multi-AS, or scale >= 50 selects Hierarchical OSPF + eBGP."""
        # Trigger 1: Multi-site / cloud
        d1 = RoutingEngine.evaluate(subnet_count=10, single_as=True, multi_site_or_cloud=True)
        assert "Hierarchical Multi-Area OSPF + eBGP" in d1.selected_protocol
        assert "multi-site/cloud boundary" in d1.rationale

        # Trigger 2: Multi-AS
        d2 = RoutingEngine.evaluate(subnet_count=10, single_as=False, multi_site_or_cloud=False)
        assert "Hierarchical Multi-Area OSPF + eBGP" in d2.selected_protocol
        assert "multi-AS administrative segregation" in d2.rationale

        # Trigger 3: Subnet threshold >= 50
        d3 = RoutingEngine.evaluate(subnet_count=55, single_as=True, multi_site_or_cloud=False)
        assert "Hierarchical Multi-Area OSPF + eBGP" in d3.selected_protocol
        assert "55 >= 50" in d3.rationale


# ==============================================================================
# 4. End-to-End Presets & Cisco IOS Config Generation Tests
# ==============================================================================

class TestPresetArchitecturesAndConfigs:
    """Test end-to-end generation across the 3 mandatory preset profiles."""

    @pytest.mark.parametrize("preset_name", ["campus_lan", "metro_man", "global_wan"])
    def test_preset_full_compilation(self, preset_name):
        profile = get_preset(preset_name)
        l1 = L1MediaEngine.evaluate(profile.distance_m, profile.requested_media)
        allocations = VLSMAllocator.allocate(
            profile.root_prefix, profile.host_requests, vlan_start=profile.vlan_base
        )
        routing = RoutingEngine.evaluate(
            subnet_count=len(allocations),
            single_as=profile.single_as,
            multi_site_or_cloud=profile.multi_site_or_cloud,
        )

        gen = CiscoConfigGenerator(profile, l1, allocations, routing)
        config = gen.generate_full_config()

        # Structural assertions
        assert "version 15.2" in config
        assert "spanning-tree mode rapid-pvst" in config
        assert "switchport trunk allowed vlan" in config
        assert "ACL_PERMIT_INTERNAL_SUBNETS" in config

        # Verify all subnets are in OSPF and ACLs with correct wildcard
        for a in allocations:
            assert f"interface Vlan{a.vlan_id}" in config
            assert f"network {a.network_address} {a.wildcard_mask}" in config
            assert f"permit {a.network_address} {a.wildcard_mask}" in config

        # Preset-specific features
        if preset_name == "campus_lan":
            assert l1.selected_media == "OM4 MMF (10GBASE-SR)"
            assert "Single-Area OSPFv2" in routing.selected_protocol
        elif preset_name == "metro_man":
            assert l1.selected_media == "OS2 SMF (10GBASE-LR/ER)"
            assert "standby" in config
            assert "POLICY_SUB5MS_CORE" in config
        elif preset_name == "global_wan":
            assert l1.selected_media == "OS2 SMF (10GBASE-LR/ER)"
            assert "router bgp 65001" in config
            assert "crypto isakmp" in config
            assert "Tunnel100" in config
