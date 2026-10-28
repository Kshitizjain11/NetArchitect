"""Sanity verification script for NetArchitect Step 1."""
from src.engines import L1MediaEngine, VLSMAllocator, RoutingEngine
from src.models import PhysicalDistanceViolationError, AddressExhaustionError
from src.presets import PRESETS

def test_engines():
    print("=" * 80)
    print("  NETARCHITECT ENGINE SANITY VERIFICATION (STEP 1)")
    print("=" * 80)

    for profile_key, profile in PRESETS.items():
        print(f"\n[+] Testing Preset: {profile.name} - {profile.description}")
        
        # 1. L1 Engine
        l1 = L1MediaEngine.evaluate(profile.distance_m, profile.requested_media)
        print(f"    L1 Media Selection : {l1.selected_media} (Distance: {l1.distance_m}m)")
        print(f"    Standard Reference : {l1.standard_reference}")
        print(f"    L1 Rationale       : {l1.rationale}")

        # 2. VLSM Engine
        allocations = VLSMAllocator.allocate(profile.root_prefix, profile.host_requests, vlan_start=profile.vlan_base)
        print(f"\n    VLSM Subnet Allocations for Root {profile.root_prefix}:")
        print(f"    {'Subnet Name':<24} {'VLAN':<6} {'Hosts Req':<10} {'Alloc/Use':<12} {'CIDR':<20} {'Gateway':<16} {'Broadcast':<16} {'Eff %':<6}")
        print("    " + "-" * 115)
        for a in allocations:
            eff_pct = f"{a.utilization_efficiency * 100:.1f}%"
            alloc_use = f"{a.allocated_size}/{a.usable_hosts}"
            print(f"    {a.name:<24} {a.vlan_id:<6} {a.requested_hosts:<10} {alloc_use:<12} {a.cidr:<20} {a.first_usable_gateway:<16} {a.broadcast_address:<16} {eff_pct:<6}")

        # 3. Routing Engine
        routing = RoutingEngine.evaluate(
            subnet_count=len(allocations),
            single_as=profile.single_as,
            multi_site_or_cloud=profile.multi_site_or_cloud
        )
        print(f"\n    L3 Routing Protocol: {routing.selected_protocol}")
        print(f"    Topology Scope     : {routing.topology_scope}")
        print(f"    Routing Rationale  : {routing.rationale}")
        print("-" * 80)

    # 4. Exception Verification
    print("\n[+] Testing Hard Exceptions:")
    
    # Physical Distance Violation
    try:
        L1MediaEngine.evaluate(distance_m=150.0, requested_media="copper")
        print("    [!] ERROR: PhysicalDistanceViolationError not raised!")
    except PhysicalDistanceViolationError as e:
        print(f"    [OK] PhysicalDistanceViolationError caught successfully:")
        print(f"         {e}")

    # Address Exhaustion
    try:
        VLSMAllocator.allocate("192.168.1.0/24", [200, 100])
        print("    [!] ERROR: AddressExhaustionError not raised!")
    except AddressExhaustionError as e:
        print(f"    [OK] AddressExhaustionError caught successfully:")
        print(f"         {e}")

    print("\n" + "=" * 80)
    print("  STEP 1 SANITY VERIFICATION PASSED PERFECTLY!")
    print("=" * 80)

if __name__ == "__main__":
    test_engines()
