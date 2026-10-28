"""Verification script for NetArchitect Step 2."""
from src.engines import L1MediaEngine, VLSMAllocator, RoutingEngine
from src.presets import PRESETS
from src.config_gen import CiscoConfigGenerator

def verify_step2():
    print("=" * 80)
    print("  NETARCHITECT CISCO IOS CONFIG GENERATOR VERIFICATION (STEP 2)")
    print("=" * 80)

    for name, profile in PRESETS.items():
        print(f"\n>>> Generating Cisco IOS Configuration for: {name}")
        l1 = L1MediaEngine.evaluate(profile.distance_m, profile.requested_media)
        allocations = VLSMAllocator.allocate(profile.root_prefix, profile.host_requests, vlan_start=profile.vlan_base)
        routing = RoutingEngine.evaluate(
            subnet_count=len(allocations),
            single_as=profile.single_as,
            multi_site_or_cloud=profile.multi_site_or_cloud
        )

        gen = CiscoConfigGenerator(profile, l1, allocations, routing)
        config_text = gen.generate_full_config()

        # Perform targeted assertions
        assert "version 15.2" in config_text
        assert "spanning-tree mode rapid-pvst" in config_text
        assert "switchport trunk encapsulation dot1q" in config_text
        assert "switchport trunk allowed vlan" in config_text
        assert "router ospf 1" in config_text
        assert "ACL_PERMIT_INTERNAL_SUBNETS" in config_text

        for a in allocations:
            assert f"vlan {a.vlan_id}" in config_text
            assert f"interface Vlan{a.vlan_id}" in config_text
            assert f"network {a.network_address} {a.wildcard_mask}" in config_text
            assert f"permit {a.network_address} {a.wildcard_mask}" in config_text

        if name == "metro_man":
            assert "standby" in config_text
            assert "POLICY_SUB5MS_CORE" in config_text
        elif name == "global_wan":
            assert "router bgp 65001" in config_text
            assert "crypto isakmp" in config_text
            assert "Tunnel100" in config_text
            assert "area 10 range" in config_text

        print(f"    [OK] Config for {name} generated successfully ({len(config_text.splitlines())} lines).")
        print(f"    [Sample Excerpt - First 25 lines of {name}]:")
        for line in config_text.splitlines()[:25]:
            print(f"      {line}")
        print("      ...")

    print("\n" + "=" * 80)
    print("  STEP 2 VERIFICATION PASSED WITH ZERO ERRORS!")
    print("=" * 80)

if __name__ == "__main__":
    verify_step2()
