"""
tests/test_input_validation.py
------------------------------
Unit tests for engine/input_validation.py.

Every test asserts meaningful behavior against the validator's documented
rules.  Tests do not weaken expected results to accommodate a broken
implementation; if a test fails, the implementation must be fixed.

Coverage areas
--------------
- Valid preset profiles pass validation.
- Missing required fields produce specific errors.
- Invalid field types are rejected.
- Out-of-range values are rejected.
- Duplicate names/IDs are detected.
- Reserved VLAN IDs are rejected.
- IPv4 network syntax errors are detected.
- OSPF/BGP rules are enforced.
- Non-blocking warnings are issued correctly.
- Custom scenario round-trip.
"""

import copy
import pytest

from engine.input_validation import (
    ValidationResult,
    ValidationError,
    validate_network_plan,
)
from profiles.presets import get_preset, CAMPUS_LAN, METRO_MAN, GLOBAL_WAN


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ok(plan: dict) -> ValidationResult:
    """Assert that a plan passes validation and return the result."""
    result = validate_network_plan(plan)
    assert result.valid, f"Expected valid plan, got errors: {result.errors}"
    return result


def _fail(plan: dict, *expected_fragments: str) -> ValidationResult:
    """
    Assert that a plan fails validation.  If *expected_fragments* are provided,
    assert that at least one error message contains each fragment.
    """
    result = validate_network_plan(plan)
    assert not result.valid, "Expected validation to fail, but it passed."
    for fragment in expected_fragments:
        assert any(fragment in e for e in result.errors), (
            f"Expected an error containing '{fragment}' but got: {result.errors}"
        )
    return result


# ---------------------------------------------------------------------------
# Preset smoke tests
# ---------------------------------------------------------------------------

class TestPresetValidity:
    """All three preset profiles must pass validation without blocking errors."""

    def test_campus_lan_preset_is_valid(self):
        plan = get_preset(CAMPUS_LAN)
        _ok(plan)

    def test_metro_man_preset_is_valid(self):
        plan = get_preset(METRO_MAN)
        _ok(plan)

    def test_global_wan_preset_is_valid(self):
        plan = get_preset(GLOBAL_WAN)
        _ok(plan)

    def test_metro_man_has_latency_warning(self):
        """Metro MAN specifies a latency target, which must generate a planning warning."""
        plan = get_preset(METRO_MAN)
        result = validate_network_plan(plan)
        assert any("latency" in w.lower() for w in result.warnings), (
            f"Expected a latency warning; got warnings: {result.warnings}"
        )

    def test_global_wan_has_cloud_link_warning(self):
        """Global WAN contains a 0 m cloud link, which should trigger a warning."""
        plan = get_preset(GLOBAL_WAN)
        result = validate_network_plan(plan)
        assert any("virtual" in w.lower() or "cloud" in w.lower() for w in result.warnings), (
            f"Expected a cloud/virtual link warning; got: {result.warnings}"
        )

    def test_get_preset_deep_copy(self):
        """get_preset() must return a deep copy — mutations must not affect the master."""
        p1 = get_preset(CAMPUS_LAN)
        p1["sites"].clear()
        p2 = get_preset(CAMPUS_LAN)
        assert len(p2["sites"]) == 3, "Mutating returned preset should not affect the master."

    def test_get_preset_unknown_id_raises_key_error(self):
        with pytest.raises(KeyError, match="unknown_profile"):
            get_preset("unknown_profile")


# ---------------------------------------------------------------------------
# Scenario field
# ---------------------------------------------------------------------------

class TestScenarioField:

    def test_missing_scenario_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        del plan["scenario"]
        _fail(plan, "scenario")

    def test_empty_scenario_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["scenario"] = ""
        _fail(plan, "scenario")

    def test_unknown_scenario_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["scenario"] = "unknown"
        _fail(plan, "unknown")

    def test_custom_scenario_is_valid(self):
        plan = get_preset(CAMPUS_LAN)
        plan["scenario"] = "custom"
        _ok(plan)


# ---------------------------------------------------------------------------
# Root network
# ---------------------------------------------------------------------------

class TestRootNetwork:

    def test_missing_root_network_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        del plan["root_network"]
        _fail(plan, "root_network")

    def test_invalid_cidr_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["root_network"] = "not_an_ip"
        _fail(plan, "root_network")

    def test_host_bits_set_is_error(self):
        """10.10.1.0/16 has host bits set — strict parsing must reject it."""
        plan = get_preset(CAMPUS_LAN)
        plan["root_network"] = "10.10.1.0/16"
        _fail(plan, "root_network")

    def test_valid_ipv4_root_network(self):
        plan = get_preset(CAMPUS_LAN)
        plan["root_network"] = "192.168.0.0/24"
        # Make subnet requests fit in /24 (max 254 usable hosts)
        plan["subnet_requests"] = [{"name": "Sub1", "required_hosts": 10}]
        _ok(plan)

    def test_loopback_network_accepted(self):
        """Validation does not restrict to RFC-1918 — any valid CIDR is accepted."""
        plan = get_preset(CAMPUS_LAN)
        plan["root_network"] = "100.64.0.0/16"
        _ok(plan)


# ---------------------------------------------------------------------------
# Sites
# ---------------------------------------------------------------------------

class TestSites:

    def test_empty_sites_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["sites"] = []
        _fail(plan, "at least one site")

    def test_missing_site_name_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["sites"][0].pop("name")
        _fail(plan, "name")

    def test_duplicate_site_name_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["sites"][1]["name"] = plan["sites"][0]["name"]
        _fail(plan, "duplicate site name")

    def test_invalid_site_role_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["sites"][0]["role"] = "supercomputer"
        _fail(plan, "unknown role")

    def test_invalid_asn_is_error(self):
        plan = get_preset(GLOBAL_WAN)
        plan["sites"][0]["asn"] = -1
        _fail(plan, "ASN")

    def test_asn_zero_is_error(self):
        plan = get_preset(GLOBAL_WAN)
        plan["sites"][0]["asn"] = 0
        _fail(plan, "ASN")

    def test_valid_asn_passes(self):
        plan = get_preset(GLOBAL_WAN)
        plan["sites"][0]["asn"] = 65535
        _ok(plan)


# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------

class TestLinks:

    def test_no_links_produces_warning(self):
        plan = get_preset(CAMPUS_LAN)
        plan["links"] = []
        result = validate_network_plan(plan)
        assert result.valid  # Warning, not error
        assert any("no inter-site links" in w for w in result.warnings)

    def test_link_to_unknown_site_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["links"][0]["from"] = "NonExistentSite"
        _fail(plan, "NonExistentSite")

    def test_self_loop_link_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["links"][0]["to"] = plan["links"][0]["from"]
        _fail(plan, "cannot connect a site to itself")

    def test_negative_distance_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["links"][0]["distance_m"] = -10
        _fail(plan, "non-negative")

    def test_missing_distance_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        del plan["links"][0]["distance_m"]
        _fail(plan, "distance_m")

    def test_zero_distance_produces_warning(self):
        """A virtual/cloud link (distance=0) should warn but not block."""
        plan = get_preset(CAMPUS_LAN)
        plan["links"][0]["distance_m"] = 0
        result = validate_network_plan(plan)
        assert result.valid
        assert any("virtual" in w.lower() or "cloud" in w.lower() for w in result.warnings)

    def test_non_numeric_distance_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["links"][0]["distance_m"] = "far"
        _fail(plan, "distance_m")

    def test_zero_bandwidth_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["links"][0]["bandwidth_gbps"] = 0
        _fail(plan, "bandwidth_gbps")

    def test_negative_bandwidth_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["links"][0]["bandwidth_gbps"] = -1
        _fail(plan, "bandwidth_gbps")

    def test_missing_bandwidth_produces_warning(self):
        plan = get_preset(CAMPUS_LAN)
        del plan["links"][0]["bandwidth_gbps"]
        result = validate_network_plan(plan)
        assert result.valid
        assert any("bandwidth_gbps" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# Subnet requests
# ---------------------------------------------------------------------------

class TestSubnetRequests:

    def test_empty_subnet_requests_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["subnet_requests"] = []
        _fail(plan, "at least one subnet request")

    def test_missing_required_hosts_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        del plan["subnet_requests"][0]["required_hosts"]
        _fail(plan, "required_hosts")

    def test_zero_hosts_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["subnet_requests"][0]["required_hosts"] = 0
        _fail(plan, "at least 1")

    def test_negative_hosts_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["subnet_requests"][0]["required_hosts"] = -5
        _fail(plan, "at least 1")

    def test_non_integer_hosts_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["subnet_requests"][0]["required_hosts"] = 10.5
        _fail(plan, "integer")

    def test_duplicate_subnet_name_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["subnet_requests"][1]["name"] = plan["subnet_requests"][0]["name"]
        _fail(plan, "duplicate subnet name")

    def test_exceeding_address_space_produces_warning(self):
        """More hosts requested than the root network can hold → warning (VLSM allocator will error)."""
        plan = get_preset(CAMPUS_LAN)
        plan["root_network"] = "192.168.0.0/24"
        plan["subnet_requests"] = [{"name": "Huge", "required_hosts": 1000}]
        result = validate_network_plan(plan)
        assert any("exhaustion" in w.lower() or "exceeds" in w.lower() for w in result.warnings)

    def test_one_host_is_accepted(self):
        """required_hosts=1 is the minimum valid value (allocates a /30)."""
        plan = get_preset(CAMPUS_LAN)
        plan["subnet_requests"][0]["required_hosts"] = 1
        _ok(plan)

    def test_max_valid_host_count_accepted(self):
        plan = get_preset(CAMPUS_LAN)
        plan["root_network"] = "10.0.0.0/8"
        plan["subnet_requests"] = [{"name": "Big", "required_hosts": 16_777_214}]
        _ok(plan)

    def test_host_count_above_maximum_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["subnet_requests"][0]["required_hosts"] = 16_777_215
        _fail(plan, "16,777,214")


# ---------------------------------------------------------------------------
# VLANs
# ---------------------------------------------------------------------------

class TestVlans:

    def test_reserved_vlan_1_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["vlans"][0]["id"] = 1
        _fail(plan, "reserved")

    def test_reserved_vlan_1002_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["vlans"][0]["id"] = 1002
        _fail(plan, "reserved")

    def test_vlan_id_below_minimum_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["vlans"][0]["id"] = 0
        _fail(plan, "outside the valid range")

    def test_vlan_id_above_maximum_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["vlans"][0]["id"] = 4095
        _fail(plan, "outside the valid range")

    def test_duplicate_vlan_id_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["vlans"][1]["id"] = plan["vlans"][0]["id"]
        _fail(plan, "duplicate VLAN ID")

    def test_duplicate_vlan_name_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["vlans"][1]["name"] = plan["vlans"][0]["name"]
        _fail(plan, "duplicate VLAN name")

    def test_missing_vlan_name_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["vlans"][0]["name"] = ""
        _fail(plan, "'name' is required")

    def test_no_vlans_produces_warning(self):
        plan = get_preset(CAMPUS_LAN)
        plan["vlans"] = []
        result = validate_network_plan(plan)
        assert result.valid
        assert any("vlan" in w.lower() for w in result.warnings)

    def test_vlan_id_4094_is_valid(self):
        plan = get_preset(CAMPUS_LAN)
        plan["vlans"][0]["id"] = 4094
        _ok(plan)

    def test_vlan_id_2_is_valid(self):
        plan = get_preset(CAMPUS_LAN)
        plan["vlans"][0]["id"] = 2
        _ok(plan)


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

class TestRouting:

    def test_unknown_routing_protocol_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["routing_protocol"] = "rip"
        _fail(plan, "unknown protocol")

    def test_ospf_without_areas_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["ospf_areas"] = []
        _fail(plan, "ospf_areas")

    def test_multi_area_ospf_requires_area_0(self):
        plan = get_preset(GLOBAL_WAN)
        # Remove area 0 from the areas list
        plan["ospf_areas"] = [a for a in plan["ospf_areas"] if a["area_id"] != 0]
        _fail(plan, "backbone area")

    def test_bgp_protocol_without_peers_is_error(self):
        plan = get_preset(GLOBAL_WAN)
        plan["bgp_peers"] = []
        _fail(plan, "bgp_peers")

    def test_ibgp_same_as_produces_warning(self):
        plan = get_preset(GLOBAL_WAN)
        plan["bgp_peers"][0]["remote_as"] = plan["bgp_peers"][0]["local_as"]
        result = validate_network_plan(plan)
        assert result.valid  # Warning, not error
        assert any("iBGP" in w for w in result.warnings)

    def test_duplicate_ospf_area_id_is_error(self):
        plan = get_preset(GLOBAL_WAN)
        plan["ospf_areas"].append({"area_id": 0, "networks": ["Duplicate"]})
        _fail(plan, "duplicate area_id")

    def test_static_routing_is_valid(self):
        plan = get_preset(CAMPUS_LAN)
        plan["routing_protocol"] = "static"
        # Static routing doesn't require ospf_areas — but the plan still has them;
        # remove to confirm static alone is accepted.
        plan.pop("ospf_areas", None)
        _ok(plan)

    def test_bgp_peer_missing_local_as_is_error(self):
        plan = get_preset(GLOBAL_WAN)
        del plan["bgp_peers"][0]["local_as"]
        _fail(plan, "local_as")


# ---------------------------------------------------------------------------
# Optional flags and native VLAN
# ---------------------------------------------------------------------------

class TestOptionalFlags:

    def test_non_boolean_poe_flag_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["poe_required"] = "yes"
        _fail(plan, "poe_required")

    def test_non_boolean_qos_flag_is_error(self):
        plan = get_preset(METRO_MAN)
        plan["qos_required"] = 1
        _fail(plan, "qos_required")

    def test_invalid_stp_mode_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["stp_mode"] = "spanningtree"
        _fail(plan, "stp_mode")

    def test_invalid_redundancy_mode_is_error(self):
        plan = get_preset(METRO_MAN)
        plan["redundancy"] = "active_passive"
        _fail(plan, "redundancy")

    def test_native_vlan_1_produces_warning(self):
        plan = get_preset(CAMPUS_LAN)
        plan["native_vlan"] = 1
        result = validate_network_plan(plan)
        assert result.valid
        assert any("native" in w.lower() for w in result.warnings)

    def test_native_vlan_out_of_range_is_error(self):
        plan = get_preset(CAMPUS_LAN)
        plan["native_vlan"] = 5000
        _fail(plan, "native_vlan")

    def test_negative_latency_target_is_error(self):
        plan = get_preset(METRO_MAN)
        plan["latency_target_ms"] = -1
        _fail(plan, "latency_target_ms")

    def test_zero_latency_target_is_error(self):
        plan = get_preset(METRO_MAN)
        plan["latency_target_ms"] = 0
        _fail(plan, "latency_target_ms")


# ---------------------------------------------------------------------------
# Plan type check
# ---------------------------------------------------------------------------

class TestPlanType:

    def test_non_dict_plan_is_error(self):
        result = validate_network_plan("not a dict")  # type: ignore[arg-type]
        assert not result.valid
        assert any("dict" in e for e in result.errors)

    def test_none_plan_is_error(self):
        result = validate_network_plan(None)  # type: ignore[arg-type]
        assert not result.valid
