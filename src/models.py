"""Data models and custom exceptions for NetArchitect."""
from dataclasses import dataclass, field
from typing import List, Optional, Union


class PhysicalDistanceViolationError(Exception):
    """Raised when requested physical media violates physical attenuation or standard distance constraints."""
    pass


class AddressExhaustionError(Exception):
    """Raised when VLSM host allocation requests exceed the available capacity of the root prefix."""
    pass


@dataclass(frozen=True)
class SubnetRequest:
    """Request for host capacity within a subnet/VLAN."""
    name: str
    hosts: int
    vlan_id: Optional[int] = None


@dataclass(frozen=True)
class SubnetAllocation:
    """Deterministic result of a VLSM subnet block allocation."""
    name: str
    vlan_id: int
    requested_hosts: int
    allocated_size: int
    usable_hosts: int
    network_address: str
    prefix_len: int
    netmask: str
    wildcard_mask: str
    first_usable_gateway: str
    last_usable_host: str
    broadcast_address: str
    utilization_efficiency: float

    @property
    def cidr(self) -> str:
        return f"{self.network_address}/{self.prefix_len}"


@dataclass(frozen=True)
class L1Decision:
    """L1 Physical Media selection and engineering rationale."""
    selected_media: str
    standard_reference: str
    rationale: str
    distance_m: float
    requested_media: Optional[str] = None


@dataclass(frozen=True)
class RoutingDecision:
    """L3 Routing Protocol selection and engineering rationale."""
    selected_protocol: str
    topology_scope: str
    rationale: str
    subnet_count: int
    is_multi_as_or_cloud: bool


@dataclass
class NetworkProfile:
    """Full architectural specification for a network deployment scenario."""
    name: str
    description: str
    distance_m: float
    root_prefix: str
    host_requests: List[Union[int, SubnetRequest]]
    requested_media: Optional[str] = None
    single_as: bool = True
    multi_site_or_cloud: bool = False
    features: List[str] = field(default_factory=list)
    vlan_base: int = 10
