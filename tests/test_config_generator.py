"""
tests/test_config_generator.py
-------------------------------
Unit and regression tests for generator/cisco_ios.py.

Coverage per PROJECT_SPEC.md Section 11 (Configuration tests):
  - IP addresses and masks match allocations
  - VLANs and interface references are consistent
  - Routing statements match actual networks and areas
  - ACLs are not unintentionally unrestricted
  - Missing parameters are represented as explicit structured placeholders
  - Profile-specific features:
      * Campus LAN: RSTP root/backup priorities (4096 / 8192), explicit VLAN trunks, SVIs
      * Metro MAN: QoS class-maps (DSCP EF, AF41, AF21) & policy-map applied to EVPL
      * Global WAN: IPsec/IKEv2 VPN proposals, keyrings, transform-sets, and tunnel interfaces
  - Automated exports: campus_lan_config.txt, metro_man_config.txt, global_wan_config.txt
"""

import os
import pytest
from profiles.presets import (
    CAMPUS_LAN_PRESET,
    METRO_MAN_PRESET,
    GLOBAL_WAN_PRESET,
)
from engine.vlsm_allocator import allocate_from_plan
from engine.routing_engine import decide_routing
from engine.topology_engine import plan_topology
from generator.cisco_ios import (
    CiscoDeviceConfig,
    NetworkConfigResult,
    generate_device_config,
    generate_network_config,
    export_preset_configs,
)


class TestCampusLanConfiguration:
    """Verify Campus LAN profile configuration generation."""

    @pytest.fixture
    def campus_result(self):
        return generate_network_config(CAMPUS_LAN_PRESET)

    def test_devices_present(self, campus_result):
        hostnames = [d.hostname for d in campus_result.device_configs]
        assert "Building-A" in hostnames
        assert "Building-B" in hostnames
        assert "Building-C" in hostnames

    def test_stp_root_priorities(self, campus_result):
        # Building-A is Core (root -> 4096)
        core_cfg = next(d for d in campus_result.device_configs if d.hostname == "Building-A")
        assert "spanning-tree vlan 1-4094 priority 4096" in core_cfg.config_text

        # Building-B is Distribution (backup -> 8192)
        dist_cfg = next(d for d in campus_result.device_configs if d.hostname == "Building-B")
        assert "spanning-tree vlan 1-4094 priority 8192" in dist_cfg.config_text

    def test_explicit_vlan_trunks_and_native_vlan(self, campus_result):
        core_cfg = next(d for d in campus_result.device_configs if d.hostname == "Building-A")
        # Native VLAN 999 must be configured
        assert "switchport trunk native vlan 999" in core_cfg.config_text
        # Trunk must explicitly prune VLANs (not 'all')
        assert "switchport trunk allowed vlan" in core_cfg.config_text
        assert "switchport trunk allowed vlan all" not in core_cfg.config_text
        assert "999" in core_cfg.config_text

    def test_svi_addresses_match_vlsm(self, campus_result):
        vlsm = allocate_from_plan(CAMPUS_LAN_PRESET)
        core_cfg = next(d for d in campus_result.device_configs if d.hostname == "Building-A")

        # Every allocated subnet's gateway must appear as an SVI IP
        for alloc in vlsm.allocations:
            if alloc.status == "allocated" and "mgmt" not in alloc.name.lower():
                expected_svi = f"ip address {alloc.gateway} {alloc.subnet_mask}"
                assert expected_svi in core_cfg.config_text

    def test_ospf_network_statements_match_vlsm(self, campus_result):
        vlsm = allocate_from_plan(CAMPUS_LAN_PRESET)
        core_cfg = next(d for d in campus_result.device_configs if d.hostname == "Building-A")
        assert "router ospf" in core_cfg.config_text

        # Every allocated subnet must have a network statement with correct wildcard mask
        for alloc in vlsm.allocations:
            if alloc.status == "allocated":
                expected_stmt = f"network {alloc.network_address} {alloc.wildcard_mask} area 0"
                assert expected_stmt in core_cfg.config_text


class TestMetroManConfiguration:
    """Verify Metro MAN profile configuration generation (QoS, dual homing)."""

    @pytest.fixture
    def metro_result(self):
        return generate_network_config(METRO_MAN_PRESET)

    def test_qos_class_and_policy_maps(self, metro_result):
        hq_cfg = next(d for d in metro_result.device_configs if d.hostname == "HQ")
        # DiffServ class-maps
        assert "class-map match-any CM-VOICE" in hq_cfg.config_text
        assert "match ip dscp ef" in hq_cfg.config_text
        assert "class-map match-any CM-VIDEO" in hq_cfg.config_text
        assert "match ip dscp af41" in hq_cfg.config_text
        assert "class-map match-any CM-CRITICAL-DATA" in hq_cfg.config_text
        assert "match ip dscp af21" in hq_cfg.config_text

        # Policy map definition and service-policy attachment
        assert "policy-map QOS-WAN-POLICY" in hq_cfg.config_text
        assert "priority percent 20" in hq_cfg.config_text
        assert "service-policy output QOS-WAN-POLICY" in hq_cfg.config_text

    def test_metro_devices_present(self, metro_result):
        hostnames = [d.hostname for d in metro_result.device_configs]
        assert "HQ" in hostnames
        assert "Site-B" in hostnames
        assert "Site-C" in hostnames


class TestGlobalWanConfiguration:
    """Verify Global WAN profile configuration generation (IPsec, BGP, multi-area)."""

    @pytest.fixture
    def wan_result(self):
        return generate_network_config(GLOBAL_WAN_PRESET)

    def test_ipsec_crypto_templates(self, wan_result):
        hub_cfg = next(d for d in wan_result.device_configs if d.hostname == "City-Mumbai")
        assert "crypto ikev2 proposal PROP-NETARCHITECT" in hub_cfg.config_text
        assert "encryption aes-cbc-256" in hub_cfg.config_text
        assert "integrity sha256" in hub_cfg.config_text
        assert "group 14" in hub_cfg.config_text
        assert "crypto ipsec transform-set TS-NETARCHITECT" in hub_cfg.config_text
        assert "interface Tunnel" in hub_cfg.config_text

    def test_bgp_peering_statements(self, wan_result):
        hub_cfg = next(d for d in wan_result.device_configs if d.hostname == "City-Mumbai")
        assert "router bgp 65001" in hub_cfg.config_text
        assert "remote-as 65002" in hub_cfg.config_text

    def test_explicit_placeholders_used_safely(self, wan_result):
        hub_cfg = next(d for d in wan_result.device_configs if d.hostname == "City-Mumbai")
        # Must never invent real credentials or peer IPs
        assert "<ENTER_SECURE_ENABLE_SECRET>" in hub_cfg.placeholders
        assert any("<REMOTE-PEER" in p or "<BGP_NEIGHBOR" in p for p in hub_cfg.placeholders)
        assert any("<PSK" in p for p in hub_cfg.placeholders)


class TestAclQuality:
    """Verify ACLs are secure and not unintentionally unrestricted."""

    def test_management_vty_acl_restricts_access(self):
        result = generate_network_config(CAMPUS_LAN_PRESET)
        core_cfg = next(d for d in result.device_configs if d.hostname == "Building-A")
        assert "ip access-list standard ACL-MGMT-INBOUND" in core_cfg.config_text
        assert "deny any log" in core_cfg.config_text
        assert "access-class ACL-MGMT-INBOUND in" in core_cfg.config_text


class TestExportsCreation:
    """Verify export_preset_configs creates all 3 mandatory deliverable files."""

    def test_export_preset_configs_creates_files(self, tmp_path):
        out_dir = str(tmp_path / "test_exports")
        created = export_preset_configs(output_dir=out_dir)

        assert "campus_lan" in created
        assert "metro_man" in created
        assert "global_wan" in created

        for path in created.values():
            assert os.path.exists(path)
            assert os.path.getsize(path) > 1000  # Substantial valid config content
