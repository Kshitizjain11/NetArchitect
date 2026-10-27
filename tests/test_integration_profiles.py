"""
tests/test_integration_profiles.py
----------------------------------
End-to-end integration tests for NetArchitect.

Coverage per PROJECT_SPEC.md Section 11 (Integration tests):
  - Run Campus LAN, Metro MAN, and Global WAN through the entire engine pipeline
  - Validate output plans, media decisions, VLSM allocations, routing, and topology
  - Generate and verify all three export deliverables
  - Confirm invalid inputs fail safely without uncaught crashes
"""

import os
import pytest
from profiles.presets import (
    CAMPUS_LAN_PRESET,
    METRO_MAN_PRESET,
    GLOBAL_WAN_PRESET,
    get_preset,
)
from engine.input_validation import validate_network_plan, ValidationError
from engine.media_engine import evaluate_all_links, evaluate_link, PhysicalDistanceViolationError
from engine.vlsm_allocator import allocate_from_plan, allocate_vlsm, AddressExhaustionError
from engine.routing_engine import decide_routing, ProtocolChoice
from engine.topology_engine import plan_topology
from engine.explainability import generate_explainability_report
from generator.cisco_ios import generate_network_config, export_preset_configs


class TestFullPipelineCampusLan:
    """End-to-end execution of Campus LAN profile."""

    def test_pipeline_runs_and_matches(self):
        plan = get_preset("campus_lan")
        # 1. Validation
        v_res = validate_network_plan(plan)
        assert v_res.valid

        # 2. Media Evaluation
        media_results = evaluate_all_links(plan["links"])
        assert len(media_results) == 3
        # All campus links are 180m, 320m, 250m -> OM4 multimode fiber
        for link in media_results:
            assert link["media_decision"].recommended_medium.value == "mmf"
            assert "OM4" in link["media_decision"].cable_type

        # 3. VLSM Allocation
        vlsm = allocate_from_plan(plan)
        assert vlsm.success
        assert len(vlsm.allocations) == 8
        assert vlsm.total_root_addresses == 65536

        # 4. Routing Decision
        routing = decide_routing(plan, subnet_count=len(vlsm.allocations))
        assert routing.protocol == ProtocolChoice.OSPF
        assert routing.single_area_ospf

        # 5. Topology Plan
        topology = plan_topology(plan, routing, vlsm)
        assert len(topology.devices) == 3
        assert topology.stp_mode == "rstp"

        # 6. Explainability Report
        report = generate_explainability_report(plan, vlsm_result=vlsm, routing_decision=routing, topology_plan=topology)
        assert len(report.media_justifications) == 3
        assert len(report.vlsm_justifications) == 8
        assert len(report.routing_justifications) >= 1
        assert len(report.topology_justifications) >= 2

        # 7. Cisco Config Generation
        cfg_bundle = generate_network_config(plan, vlsm_result=vlsm, topology_plan=topology)
        assert len(cfg_bundle.device_configs) == 3
        assert "Building-A" in cfg_bundle.combined_config_text


class TestFullPipelineMetroMan:
    """End-to-end execution of Metro MAN profile."""

    def test_pipeline_runs_and_matches(self):
        plan = get_preset("metro_man")
        # 1. Validation
        v_res = validate_network_plan(plan)
        assert v_res.valid

        # 2. Media Evaluation
        media_results = evaluate_all_links(plan["links"])
        # Metro links are 15km and 22km -> OS2 SMF
        for link in media_results:
            assert link["media_decision"].recommended_medium.value == "smf"
            assert "OS2" in link["media_decision"].cable_type

        # 3. VLSM Allocation
        vlsm = allocate_from_plan(plan)
        assert vlsm.success

        # 4. Routing Decision
        routing = decide_routing(plan, subnet_count=len(vlsm.allocations))
        assert routing.qos_required

        # 5. Topology Plan
        topology = plan_topology(plan, routing, vlsm)
        assert len(topology.qos_policies) > 0

        # 6. Cisco Config Generation
        cfg_bundle = generate_network_config(plan, vlsm_result=vlsm, topology_plan=topology)
        assert "policy-map QOS-WAN-POLICY" in cfg_bundle.combined_config_text


class TestFullPipelineGlobalWan:
    """End-to-end execution of Global WAN profile."""

    def test_pipeline_runs_and_matches(self):
        plan = get_preset("global_wan")
        # 1. Validation
        v_res = validate_network_plan(plan)
        assert v_res.valid

        # 2. VLSM Allocation
        vlsm = allocate_from_plan(plan)
        assert vlsm.success

        # 3. Routing Decision (Multi-AS / Cloud -> BGP + OSPF)
        routing = decide_routing(plan, subnet_count=len(vlsm.allocations))
        assert routing.protocol == ProtocolChoice.MULTI_AREA_OSPF_BGP
        assert len(routing.bgp_peers) > 0
        assert routing.ipsec_vpn_required

        # 4. Topology Plan
        topology = plan_topology(plan, routing, vlsm)
        assert len(topology.ipsec_tunnels) > 0

        # 5. Cisco Config Generation
        cfg_bundle = generate_network_config(plan, vlsm_result=vlsm, topology_plan=topology)
        assert "crypto ikev2 proposal PROP-NETARCHITECT" in cfg_bundle.combined_config_text
        assert "router bgp 65001" in cfg_bundle.combined_config_text


class TestInvalidInputsFailSafely:
    """Ensure invalid inputs fail with clean errors and never unhandled exceptions."""

    def test_copper_over_100m_raises_or_reports_violation(self):
        # Structured violation
        dec = evaluate_link(150.0, requested_medium="copper", raise_on_violation=False)
        assert dec.violation
        assert "exceeds the 100 m" in dec.violation_message

        # Hard violation
        with pytest.raises(PhysicalDistanceViolationError):
            evaluate_link(150.0, requested_medium="copper", raise_on_violation=True)

    def test_vlsm_exhaustion_handled(self):
        res = allocate_vlsm("192.168.1.0/24", [{"name": "TooBig", "required_hosts": 300}])
        assert not res.success
        assert len(res.errors) > 0
        assert res.allocations[0].status == "exhaustion_error"
        assert "exhausted" in res.allocations[0].explanation.lower()


class TestExportsGeneratedAndPopulated:
    """Ensure the three deliverable files exist and contain genuine configuration data."""

    def test_exports_populated(self):
        paths = export_preset_configs("exports")
        for key, p in paths.items():
            assert os.path.exists(p)
            with open(p, "r", encoding="utf-8") as f:
                content = f.read()
            assert "NetArchitect Cisco IOS Configuration" in content
            assert "hostname" in content
            assert "interface" in content
