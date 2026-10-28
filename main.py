"""NetArchitect CLI - Automated Network Architecture & Cisco IOS Provisioning Utility."""
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from src.models import (
    AddressExhaustionError,
    L1Decision,
    NetworkProfile,
    PhysicalDistanceViolationError,
    RoutingDecision,
    SubnetAllocation,
    SubnetRequest,
)
from src.engines import L1MediaEngine, VLSMAllocator, RoutingEngine
from src.presets import PRESETS, get_preset
from src.config_gen import CiscoConfigGenerator


PROFILE_EXPORT_MAP: Dict[str, str] = {
    "campus_lan": "profile1_campus_lan.cfg",
    "metro_man": "profile2_metro_man.cfg",
    "global_wan": "profile3_global_wan.cfg",
}


def load_custom_profile(file_path: Path) -> NetworkProfile:
    """Load and validate custom network profile from JSON file."""
    if not file_path.exists():
        raise FileNotFoundError(f"Custom specification file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Validate required fields
    required = ["name", "distance_m", "root_prefix", "host_requests"]
    for req in required:
        if req not in data:
            raise ValueError(f"Missing mandatory field in custom JSON: '{req}'")

    raw_requests = data["host_requests"]
    host_requests: List[SubnetRequest] = []
    for idx, item in enumerate(raw_requests):
        if isinstance(item, int):
            host_requests.append(SubnetRequest(name=f"Subnet_{idx + 1}", hosts=item, vlan_id=None))
        elif isinstance(item, dict):
            host_requests.append(
                SubnetRequest(
                    name=item.get("name", f"Subnet_{idx + 1}"),
                    hosts=int(item["hosts"]),
                    vlan_id=item.get("vlan_id"),
                )
            )
        else:
            raise TypeError(f"Invalid host request entry: {item}")

    return NetworkProfile(
        name=data["name"],
        description=data.get("description", f"Custom Architecture for {data['name']}"),
        distance_m=float(data["distance_m"]),
        root_prefix=data["root_prefix"],
        host_requests=host_requests,
        requested_media=data.get("requested_media"),
        single_as=data.get("single_as", True),
        multi_site_or_cloud=data.get("multi_site_or_cloud", False),
        features=data.get("features", ["802.1Q VLANs", "RSTP"]),
        vlan_base=data.get("vlan_base", 10),
    )


def process_network_profile(
    profile: NetworkProfile,
    export_dir: Optional[Path] = None,
    custom_filename: Optional[str] = None,
) -> str:
    """
    Execute algorithmic L1-L3 engines, print engineering report, and export Cisco IOS configuration.
    """
    print("=" * 80)
    print(f"  NETARCHITECT COMPILATION: {profile.name.upper()}")
    print(f"  {profile.description}")
    print("=" * 80)

    # 1. L1 Physical Media Evaluation
    l1_decision: L1Decision = L1MediaEngine.evaluate(
        distance_m=profile.distance_m,
        requested_media=profile.requested_media,
    )
    print(f"\n[L1 Physical Layer Selection]")
    print(f"  Distance          : {l1_decision.distance_m:.1f} meters ({l1_decision.distance_m / 1000.0:.2f} km)")
    print(f"  Selected Media    : {l1_decision.selected_media}")
    print(f"  Standard Standard : {l1_decision.standard_reference}")
    print(f"  Rationale         : {l1_decision.rationale}")

    # 2. L3 VLSM Bitwise Allocation
    allocations: List[SubnetAllocation] = VLSMAllocator.allocate(
        root_prefix=profile.root_prefix,
        host_requests=profile.host_requests,
        vlan_start=profile.vlan_base,
    )

    print(f"\n[L3 VLSM Subnet Allocation Table (Root: {profile.root_prefix})]")
    print(f"  {'VLAN':<5} {'Subnet Name':<22} {'CIDR':<19} {'Netmask':<16} {'Gateway':<15} {'Hosts (Req/Alloc)':<18} {'Eff %':<6}")
    print("  " + "-" * 105)
    for a in allocations:
        eff_str = f"{a.utilization_efficiency * 100:.1f}%"
        h_str = f"{a.requested_hosts} / {a.usable_hosts}"
        print(f"  {a.vlan_id:<5} {a.name:<22} {a.cidr:<19} {a.netmask:<16} {a.first_usable_gateway:<15} {h_str:<18} {eff_str:<6}")

    # 3. L3 Routing Engine Evaluation
    routing_decision: RoutingDecision = RoutingEngine.evaluate(
        subnet_count=len(allocations),
        single_as=profile.single_as,
        multi_site_or_cloud=profile.multi_site_or_cloud,
    )
    print(f"\n[L3 Dynamic Routing Protocol Decision]")
    print(f"  Selected Protocol : {routing_decision.selected_protocol}")
    print(f"  Topology Scope    : {routing_decision.topology_scope}")
    print(f"  Rationale         : {routing_decision.rationale}")

    # 4. Generate Cisco IOS Configuration
    generator = CiscoConfigGenerator(
        profile=profile,
        l1=l1_decision,
        allocations=allocations,
        routing=routing_decision,
    )
    config_output = generator.generate_full_config()

    # 5. Export to File
    if export_dir:
        export_dir.mkdir(parents=True, exist_ok=True)
        if custom_filename:
            file_name = custom_filename
        else:
            file_name = PROFILE_EXPORT_MAP.get(profile.name, f"{profile.name}.cfg")

        dest_path = export_dir / file_name
        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(config_output)

        print(f"\n[Export Status]")
        print(f"  Deployment Config : {dest_path.resolve()} ({len(config_output.splitlines())} lines written)")

    print("-" * 80 + "\n")
    return config_output


def main():
    parser = argparse.ArgumentParser(
        prog="netarchitect",
        description="Deterministic Network Architecture & Cisco IOS Provisioning Engine",
    )
    parser.add_argument(
        "--profile",
        choices=["campus_lan", "metro_man", "global_wan", "all"],
        help="Execute algorithmic provisioning for a preset profile or 'all'",
    )
    parser.add_argument(
        "--custom",
        type=Path,
        help="Path to custom JSON network architecture specification",
    )
    parser.add_argument(
        "--export-dir",
        type=Path,
        default=Path("exports"),
        help="Output directory for generated Cisco IOS configuration files (default: exports)",
    )

    args = parser.parse_args()

    if not args.profile and not args.custom:
        parser.print_help()
        sys.exit(1)

    try:
        if args.custom:
            profile = load_custom_profile(args.custom)
            process_network_profile(profile, export_dir=args.export_dir)

        elif args.profile == "all":
            for profile_key in ["campus_lan", "metro_man", "global_wan"]:
                profile = get_preset(profile_key)
                process_network_profile(profile, export_dir=args.export_dir)

        else:
            profile = get_preset(args.profile)
            process_network_profile(profile, export_dir=args.export_dir)

    except (PhysicalDistanceViolationError, AddressExhaustionError, ValueError, FileNotFoundError) as err:
        print(f"\n[ENGINE CRITICAL ERROR] {err}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
