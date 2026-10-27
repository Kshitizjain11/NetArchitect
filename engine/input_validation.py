"""
engine/input_validation.py
--------------------------
Validates all network plan inputs before they are passed to the decision
engines.  The validator is the single authoritative gatekeeper — no engine
module should operate on unvalidated data.

Design rules
------------
- Raise ValidationError (a plain ValueError subclass) for blocking problems.
- Collect warnings (non-blocking) in a list so callers can surface them.
- Never silently correct invalid input; report it.
- Every validated field has an explicit domain check with a message that
  names the bad value and the acceptable range/type.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ValidationError(ValueError):
    """Raised when an input value makes further engine processing impossible."""


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """
    Returned by validate_network_plan().

    Attributes
    ----------
    valid : bool
        True only when there are no blocking errors.
    errors : list[str]
        Blocking problems that must be resolved before running engines.
    warnings : list[str]
        Non-blocking issues the user should review.
    """
    valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)
        self.valid = False

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_SCENARIOS = frozenset({"campus_lan", "metro_man", "global_wan", "custom"})
VALID_ROUTING_PROTOCOLS = frozenset({
    "ospf", "multi_area_ospf", "bgp", "multi_area_ospf_bgp", "static",
})
VALID_STP_MODES = frozenset({"stp", "rstp", "mstp", "pvst", "rapid-pvst"})
VALID_SITE_ROLES = frozenset({"core", "distribution", "access", "hub", "spoke", "cloud"})
VALID_REDUNDANCY_MODES = frozenset({
    "none", "rstp", "dual_homed", "ipsec_failover", "hsrp", "vrrp",
})

# VLAN IDs 1 and 1002–1005 are reserved in Cisco IOS.
RESERVED_VLAN_IDS = frozenset({1} | set(range(1002, 1006)))
VLAN_ID_MIN = 2
VLAN_ID_MAX = 4094

# IPv4 network validation uses the standard library.  Private ranges are not
# enforced (some assignments use public addressing for illustration).

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_valid_hostname_part(name: str) -> bool:
    """True if *name* could be part of a Cisco device hostname (no spaces, length ≤63)."""
    return bool(re.match(r'^[A-Za-z0-9_\-]{1,63}$', name))


def _validate_ipv4_network(cidr: str, field_name: str, result: ValidationResult) -> bool:
    """
    Attempt to parse *cidr* as a strict IPv4 network (host bits must be zero).
    Appends an error to *result* and returns False on failure.
    """
    try:
        ipaddress.IPv4Network(cidr, strict=True)
        return True
    except ValueError as exc:
        result.add_error(f"{field_name}: invalid IPv4 network '{cidr}' — {exc}")
        return False


# ---------------------------------------------------------------------------
# Sub-validators
# ---------------------------------------------------------------------------

def _validate_sites(sites: list[dict], result: ValidationResult) -> None:
    if not sites:
        result.add_error("sites: at least one site is required.")
        return
    if len(sites) > 256:
        result.add_error(f"sites: {len(sites)} sites exceeds the supported maximum of 256.")

    seen_names: set[str] = set()
    for i, site in enumerate(sites):
        label = f"sites[{i}]"
        name = site.get("name", "")
        if not name:
            result.add_error(f"{label}: 'name' is required.")
        elif name in seen_names:
            result.add_error(f"{label}: duplicate site name '{name}'.")
        else:
            seen_names.add(name)

        role = site.get("role", "")
        if role not in VALID_SITE_ROLES:
            result.add_error(
                f"{label} ('{name}'): unknown role '{role}'. "
                f"Valid roles: {sorted(VALID_SITE_ROLES)}."
            )

        # ASN — optional, only meaningful for BGP sites
        asn = site.get("asn")
        if asn is not None:
            if not isinstance(asn, int) or asn < 1 or asn > 4_294_967_295:
                result.add_error(
                    f"{label} ('{name}'): ASN must be an integer in 1–4294967295, "
                    f"got {asn!r}."
                )


def _validate_links(
    links: list[dict],
    site_names: set[str],
    result: ValidationResult,
) -> None:
    if not links:
        result.add_warning(
            "links: no inter-site links defined. "
            "Media recommendations will be skipped."
        )
        return

    for i, link in enumerate(links):
        label = f"links[{i}]"
        frm = link.get("from", "")
        to  = link.get("to", "")

        if frm not in site_names:
            result.add_error(f"{label}: 'from' site '{frm}' is not in the sites list.")
        if to not in site_names:
            result.add_error(f"{label}: 'to' site '{to}' is not in the sites list.")
        if frm and to and frm == to:
            result.add_error(f"{label}: a link cannot connect a site to itself ('{frm}').")

        # Distance
        distance = link.get("distance_m")
        if distance is None:
            result.add_error(f"{label} ({frm}→{to}): 'distance_m' is required.")
        elif not isinstance(distance, (int, float)):
            result.add_error(f"{label} ({frm}→{to}): 'distance_m' must be a number, got {distance!r}.")
        elif distance < 0:
            result.add_error(f"{label} ({frm}→{to}): 'distance_m' must be non-negative, got {distance}.")
        elif distance == 0:
            # Cloud or virtual links are represented as 0 m — allowed with a warning.
            result.add_warning(
                f"{label} ({frm}→{to}): distance_m=0 m. "
                "Treated as a virtual/cloud link; physical media rules are not applied."
            )

        # Bandwidth
        bw = link.get("bandwidth_gbps")
        if bw is None:
            result.add_warning(f"{label} ({frm}→{to}): 'bandwidth_gbps' not specified; engine will use defaults.")
        elif not isinstance(bw, (int, float)) or bw <= 0:
            result.add_error(f"{label} ({frm}→{to}): 'bandwidth_gbps' must be a positive number, got {bw!r}.")


def _validate_subnet_requests(
    requests: list[dict],
    root_network: str,
    result: ValidationResult,
) -> None:
    """
    Validate individual subnet requests.  Full VLSM feasibility is checked by
    the VLSM allocator; here we only validate field types and basic ranges.
    """
    if not requests:
        result.add_error("subnet_requests: at least one subnet request is required.")
        return

    seen_names: set[str] = set()
    total_host_demand = 0

    for i, req in enumerate(requests):
        label = f"subnet_requests[{i}]"
        name = req.get("name", "")
        if not name:
            result.add_error(f"{label}: 'name' is required.")
        elif name in seen_names:
            result.add_error(f"{label}: duplicate subnet name '{name}'.")
        else:
            seen_names.add(name)

        hosts = req.get("required_hosts")
        if hosts is None:
            result.add_error(f"{label} ('{name}'): 'required_hosts' is required.")
        elif not isinstance(hosts, int):
            result.add_error(
                f"{label} ('{name}'): 'required_hosts' must be an integer, got {hosts!r}."
            )
        elif hosts < 1:
            result.add_error(
                f"{label} ('{name}'): 'required_hosts' must be at least 1, got {hosts}. "
                "Use required_hosts=2 for a /30 point-to-point link."
            )
        elif hosts > 16_777_214:
            result.add_error(
                f"{label} ('{name}'): 'required_hosts' {hosts} exceeds the maximum "
                "usable hosts for a /8 network (16,777,214)."
            )
        else:
            total_host_demand += hosts

    # Rough feasibility check — if the root network cannot hold the total demand,
    # warn early (exact check is in the VLSM allocator).
    if root_network and total_host_demand > 0:
        try:
            net = ipaddress.IPv4Network(root_network, strict=True)
            available = net.num_addresses - 2
            if total_host_demand > available:
                result.add_warning(
                    f"subnet_requests: total requested hosts ({total_host_demand:,}) "
                    f"exceeds available addresses in {root_network} "
                    f"({available:,}). The VLSM allocator will report exhaustion."
                )
        except ValueError:
            pass  # root_network validation error already recorded


def _validate_vlans(vlans: list[dict], result: ValidationResult) -> None:
    if not vlans:
        # VLANs are required for all three profiles but optional for custom.
        result.add_warning("vlans: no VLANs defined.")
        return

    seen_ids: set[int]   = set()
    seen_names: set[str] = set()

    for i, vlan in enumerate(vlans):
        label = f"vlans[{i}]"
        vid = vlan.get("id")
        vname = vlan.get("name", "")

        if vid is None:
            result.add_error(f"{label}: 'id' is required.")
        elif not isinstance(vid, int):
            result.add_error(f"{label}: 'id' must be an integer, got {vid!r}.")
        elif vid in RESERVED_VLAN_IDS:
            result.add_error(
                f"{label}: VLAN ID {vid} is reserved (Cisco IOS reserves 1 and 1002–1005)."
            )
        elif not (VLAN_ID_MIN <= vid <= VLAN_ID_MAX):
            result.add_error(
                f"{label}: VLAN ID {vid} is outside the valid range {VLAN_ID_MIN}–{VLAN_ID_MAX}."
            )
        elif vid in seen_ids:
            result.add_error(f"{label}: duplicate VLAN ID {vid}.")
        else:
            seen_ids.add(vid)

        if not vname:
            result.add_error(f"{label}: 'name' is required.")
        elif vname in seen_names:
            result.add_error(f"{label}: duplicate VLAN name '{vname}'.")
        else:
            seen_names.add(vname)


def _validate_routing(plan: dict, result: ValidationResult) -> None:
    proto = plan.get("routing_protocol", "")
    if proto not in VALID_ROUTING_PROTOCOLS:
        result.add_error(
            f"routing_protocol: unknown protocol '{proto}'. "
            f"Valid options: {sorted(VALID_ROUTING_PROTOCOLS)}."
        )

    ospf_areas = plan.get("ospf_areas", [])
    if proto in {"ospf", "multi_area_ospf", "multi_area_ospf_bgp"}:
        if not ospf_areas:
            result.add_error("ospf_areas: required when routing_protocol includes OSPF.")
        else:
            area_ids: set[int] = set()
            for j, area in enumerate(ospf_areas):
                aid = area.get("area_id")
                if aid is None:
                    result.add_error(f"ospf_areas[{j}]: 'area_id' is required.")
                elif not isinstance(aid, int) or aid < 0:
                    result.add_error(f"ospf_areas[{j}]: 'area_id' must be a non-negative integer, got {aid!r}.")
                elif aid in area_ids:
                    result.add_error(f"ospf_areas[{j}]: duplicate area_id {aid}.")
                else:
                    area_ids.add(aid)

        # Multi-area OSPF must have area 0 (backbone)
        if proto in {"multi_area_ospf", "multi_area_ospf_bgp"}:
            defined_ids = {a.get("area_id") for a in ospf_areas}
            if 0 not in defined_ids:
                result.add_error(
                    "ospf_areas: multi-area OSPF requires a backbone area (area_id=0)."
                )

    bgp_peers = plan.get("bgp_peers", [])
    if proto in {"bgp", "multi_area_ospf_bgp"}:
        if not bgp_peers:
            result.add_error("bgp_peers: required when routing_protocol includes BGP.")
        else:
            for k, peer in enumerate(bgp_peers):
                local_as = peer.get("local_as")
                remote_as = peer.get("remote_as")
                if local_as is None or remote_as is None:
                    result.add_error(f"bgp_peers[{k}]: 'local_as' and 'remote_as' are required.")
                elif local_as == remote_as:
                    result.add_warning(
                        f"bgp_peers[{k}]: local_as == remote_as ({local_as}). "
                        "This is iBGP, not eBGP. Confirm this is intentional."
                    )


def _validate_optional_flags(plan: dict, result: ValidationResult) -> None:
    """Validate boolean feature flags and scenario-specific fields."""
    bool_flags = ("poe_required", "qos_required", "ipsec_vpn_required", "route_summarization")
    for flag in bool_flags:
        val = plan.get(flag)
        if val is not None and not isinstance(val, bool):
            result.add_error(f"{flag}: must be true or false, got {val!r}.")

    stp = plan.get("stp_mode", "rstp")
    if stp not in VALID_STP_MODES:
        result.add_error(
            f"stp_mode: unknown mode '{stp}'. Valid modes: {sorted(VALID_STP_MODES)}."
        )

    redundancy = plan.get("redundancy", "none")
    if redundancy not in VALID_REDUNDANCY_MODES:
        result.add_error(
            f"redundancy: unknown mode '{redundancy}'. "
            f"Valid modes: {sorted(VALID_REDUNDANCY_MODES)}."
        )

    native_vlan = plan.get("native_vlan")
    if native_vlan is not None:
        if not isinstance(native_vlan, int):
            result.add_error(f"native_vlan: must be an integer, got {native_vlan!r}.")
        elif not (1 <= native_vlan <= VLAN_ID_MAX):
            # Native VLAN range is 1–4094 in Cisco IOS.
            result.add_error(
                f"native_vlan: {native_vlan} is outside the valid range 1–{VLAN_ID_MAX}."
            )
        else:
            # Using VLAN 1 as native is a common Cisco security recommendation violation.
            if native_vlan == 1:
                result.add_warning(
                    "native_vlan=1: using VLAN 1 as native is a security concern. "
                    "Consider a dedicated, unused native VLAN (e.g. 999)."
                )

    latency = plan.get("latency_target_ms")
    if latency is not None:
        if not isinstance(latency, (int, float)) or latency <= 0:
            result.add_error(
                f"latency_target_ms: must be a positive number, got {latency!r}."
            )
        else:
            result.add_warning(
                f"latency_target_ms={latency} ms: this is a planning target only. "
                "Actual latency depends on carrier SLA, queuing delay, and CPE processing. "
                "Validate against measured values after deployment."
            )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_network_plan(plan: dict[str, Any]) -> ValidationResult:
    """
    Validate a full network plan dictionary.

    Returns a ValidationResult whose `valid` flag indicates whether the plan
    can safely proceed to the engine modules.  Callers should check
    result.valid before running any engine.

    Parameters
    ----------
    plan : dict
        A network plan as produced by get_preset() or assembled from user input.

    Returns
    -------
    ValidationResult
    """
    result = ValidationResult()

    if not isinstance(plan, dict):
        result.add_error(f"plan: expected a dict, got {type(plan).__name__}.")
        return result  # Nothing else can be validated.

    # --- Scenario ---
    scenario = plan.get("scenario", "")
    if not scenario:
        result.add_error("scenario: field is required.")
    elif scenario not in VALID_SCENARIOS:
        result.add_error(
            f"scenario: unknown value '{scenario}'. "
            f"Valid scenarios: {sorted(VALID_SCENARIOS)}."
        )

    # --- Root network ---
    root_network = plan.get("root_network", "")
    if not root_network:
        result.add_error("root_network: field is required.")
    else:
        _validate_ipv4_network(root_network, "root_network", result)

    # --- Sites ---
    sites = plan.get("sites", [])
    _validate_sites(sites, result)
    site_names = {s.get("name", "") for s in sites if s.get("name")}

    # --- Links ---
    links = plan.get("links", [])
    _validate_links(links, site_names, result)

    # --- Subnet requests ---
    subnet_requests = plan.get("subnet_requests", [])
    _validate_subnet_requests(subnet_requests, root_network, result)

    # --- VLANs ---
    vlans = plan.get("vlans", [])
    _validate_vlans(vlans, result)

    # --- Routing ---
    _validate_routing(plan, result)

    # --- Optional flags ---
    _validate_optional_flags(plan, result)

    return result
