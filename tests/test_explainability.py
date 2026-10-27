"""
tests/test_explainability.py
-----------------------------
Unit tests for engine/explainability.py.

Verifies conformance with Section 9 of PROJECT_SPEC.md:
  1. Selected technology or result
  2. Actual input values
  3. Rule or threshold applied
  4. Calculation or relevant standard
  5. Technical reason
  6. Warnings, assumptions and limitations
  - Dynamic generation (explanations change when inputs change)
  - Full report generation across Campus LAN, Metro MAN, Global WAN presets.
"""

import pytest
from profiles.presets import (
    CAMPUS_LAN_PRESET,
    METRO_MAN_PRESET,
    GLOBAL_WAN_PRESET,
)
from engine.media_engine import evaluate_link, MediumType
from engine.vlsm_allocator import allocate_vlsm
from engine.routing_engine import decide_routing
from engine.topology_engine import plan_topology
from engine.explainability import (
    DecisionJustification,
    ExplainabilityReport,
    explain_media_decision,
    explain_vlsm_allocation,
    explain_routing_architecture,
    explain_topology_and_security,
    generate_explainability_report,
)


class TestSixPointJustificationStructure:
    """Ensure every justification adheres strictly to the 6 mandatory points."""

    def test_justification_fields_complete(self):
        j = DecisionJustification(
            category="media",
            subject="Link 1",
            selected_result="Cat6a copper",
            actual_inputs={"distance_m": 45, "bandwidth": "10 Gbps"},
            rule_applied="Distance <= 100 m limit",
            calculation_or_standard="IEEE 802.3an (10GBASE-T)",
            technical_reason="Copper is cost effective within 100m.",
            warnings_and_assumptions=["Channel limit includes horizontal and patch cables."],
        )
        assert j.selected_result == "Cat6a copper"
        assert j.actual_inputs["distance_m"] == 45
        assert "100 m" in j.rule_applied
        assert "802.3an" in j.calculation_or_standard
        assert "Copper" in j.technical_reason
        assert len(j.warnings_and_assumptions) == 1

        md = j.format_markdown()
        assert "Selected Technology / Result:" in md
        assert "Actual Input Values:" in md
        assert "Rule / Threshold Applied:" in md
        assert "Calculation / Standard:" in md
        assert "Technical Reason:" in md
        assert "Warnings & Assumptions:" in md


class TestDynamicMediaExplanations:
    """Verify that explanations change dynamically when distances and media change."""

    def test_copper_explanation(self):
        dec = evaluate_link(80.0, bandwidth_gbps=10.0)
        j = explain_media_decision("Core-Access", dec)
        assert "Cat6a" in j.selected_result
        assert j.actual_inputs["distance_m"] == 80.0
        assert "100 m" in j.rule_applied
        assert "10GBASE-T" in j.calculation_or_standard
        assert "within the 100 m" in j.technical_reason

    def test_om4_explanation(self):
        dec = evaluate_link(250.0, bandwidth_gbps=10.0)
        j = explain_media_decision("Building A - Building B", dec)
        assert "OM4" in j.selected_result or "MMF" in j.selected_result
        assert j.actual_inputs["distance_m"] == 250.0
        assert "400 m" in j.rule_applied
        assert "850 nm" in j.calculation_or_standard
        assert "OM4" in j.technical_reason

    def test_os2_explanation(self):
        dec = evaluate_link(22000.0, bandwidth_gbps=10.0)
        j = explain_media_decision("Metro Link", dec)
        assert "OS2" in j.selected_result or "SMF" in j.selected_result
        assert j.actual_inputs["distance_m"] == 22000.0
        assert "400 m" in j.rule_applied
        assert "OS2" in j.calculation_or_standard
        assert "22.00 km" in j.technical_reason or "22000" in j.technical_reason

    def test_virtual_link_explanation(self):
        dec = evaluate_link(0.0)
        j = explain_media_decision("Cloud Interconnect", dec)
        assert "Virtual" in j.selected_result
        assert j.actual_inputs["distance_m"] == 0.0
        assert "0 m" in j.rule_applied


class TestDynamicVlsmExplanations:
    """Verify that VLSM allocation explanations use computed math and actual values."""

    def test_vlsm_justification_math(self):
        requests = [{"name": "HR", "required_hosts": 50}]
        result = allocate_vlsm("192.168.1.0/24", requests)
        alloc = result.allocations[0]

        j = explain_vlsm_allocation(alloc, "192.168.1.0/24")
        assert "/26" in j.selected_result
        assert j.actual_inputs["requested_hosts"] == 50
        assert "2^(32 - 26) - 2 = 62" in j.rule_applied
        assert "Gateway: 192.168.1.1" in j.calculation_or_standard
        assert "Broadcast: 192.168.1.63" in j.calculation_or_standard
        assert "50 requested hosts" in j.technical_reason

    def test_vlsm_exhaustion_explanation(self):
        requests = [{"name": "Oversized", "required_hosts": 500}]
        result = allocate_vlsm("192.168.1.0/24", requests)
        alloc = result.allocations[0]

        j = explain_vlsm_allocation(alloc, "192.168.1.0/24")
        assert "Exhaustion" in j.selected_result
        assert j.actual_inputs["requested_hosts"] == 500
        assert "exhausted" in j.rule_applied.lower()


class TestDynamicRoutingExplanations:
    """Verify routing decisions produce 6-point justifications for single vs multi area vs BGP."""

    def test_single_area_ospf_justification(self):
        plan = {
            "sites": [{"name": "Campus", "role": "campus"}],
            "autonomous_systems": [65001],
            "cloud_hosted": False,
        }
        dec = decide_routing(plan, subnet_count=8)
        justifications = explain_routing_architecture(dec)
        assert len(justifications) >= 1
        j_proto = justifications[0]
        assert "OSPF (Single Area 0)" in j_proto.selected_result
        assert j_proto.actual_inputs["subnet_count"] == 8
        assert "< 50 subnets" in j_proto.rule_applied
        assert "RFC 2328" in j_proto.calculation_or_standard
        assert "Single-Area OSPF" in j_proto.technical_reason

    def test_multi_area_ospf_justification(self):
        plan = {
            "sites": [
                {"name": "SiteA", "role": "campus"},
                {"name": "SiteB", "role": "branch"},
                {"name": "SiteC", "role": "branch"},
            ],
            "autonomous_systems": [65001],
            "cloud_hosted": False,
        }
        dec = decide_routing(plan, subnet_count=60)
        justifications = explain_routing_architecture(dec)
        j_proto = justifications[0]
        assert "Multi-Area" in j_proto.selected_result
        assert j_proto.actual_inputs["subnet_count"] == 60
        assert ">= 50" in j_proto.rule_applied

    def test_ebgp_justification(self):
        plan = {
            "sites": [
                {"name": "Headquarters", "asn": 65001},
                {"name": "CloudVPC", "asn": 65002, "is_cloud": True},
            ],
            "autonomous_systems": [65001, 65002],
            "cloud_hosted": True,
        }
        dec = decide_routing(plan, subnet_count=5)
        justifications = explain_routing_architecture(dec)
        j_proto = justifications[0]
        assert "BGP" in j_proto.selected_result
        assert len(j_proto.actual_inputs["autonomous_systems"]) == 2
        assert "RFC 4271" in j_proto.calculation_or_standard


class TestPresetProfilesExplainability:
    """Run all 3 mandatory presets through generate_explainability_report."""

    def test_campus_lan_report(self):
        report = generate_explainability_report(CAMPUS_LAN_PRESET)
        assert report.scenario_name == "Campus LAN"
        assert len(report.media_justifications) > 0
        assert len(report.vlsm_justifications) > 0
        assert len(report.routing_justifications) > 0
        assert len(report.topology_justifications) > 0

        md = report.format_markdown()
        assert "# Engineering Justification Report: Campus LAN" in md
        assert "1. Physical Media Decisions" in md
        assert "2. Addressing & VLSM Subnet Allocations" in md
        assert "3. Routing Architecture Decisions" in md
        assert "4. Layer 2, Security & Resilience Decisions" in md

    def test_metro_man_report_includes_qos(self):
        report = generate_explainability_report(METRO_MAN_PRESET)
        assert report.scenario_name == "Metro MAN"
        # Should include QoS justifications
        qos_j = [j for j in report.topology_justifications if j.category == "qos"]
        assert len(qos_j) > 0
        assert "Quality of Service" in qos_j[0].subject
        assert "DSCP" in qos_j[0].calculation_or_standard

    def test_global_wan_report_includes_ipsec(self):
        report = generate_explainability_report(GLOBAL_WAN_PRESET)
        assert report.scenario_name == "Global WAN"
        # Should include IPsec justifications
        ipsec_j = [j for j in report.topology_justifications if j.category == "security"]
        assert len(ipsec_j) > 0
        assert "IPsec VPN" in ipsec_j[0].subject
        assert "AES-256" in ipsec_j[0].calculation_or_standard
