"""Cisco IOS configuration generator for NetArchitect."""
from typing import List, Optional
import ipaddress

from src.models import (
    L1Decision,
    NetworkProfile,
    RoutingDecision,
    SubnetAllocation,
)


class CiscoConfigGenerator:
    """Generates copy-paste ready, production-grade Cisco IOS configurations."""

    def __init__(
        self,
        profile: NetworkProfile,
        l1: L1Decision,
        allocations: List[SubnetAllocation],
        routing: RoutingDecision,
    ):
        self.profile = profile
        self.l1 = l1
        self.allocations = allocations
        self.routing = routing

    def generate_header(self) -> str:
        """Generate architectural engineering rationale header."""
        vlan_summary = []
        for a in self.allocations:
            eff = f"{a.utilization_efficiency * 100:.1f}%"
            vlan_summary.append(
                f"!   VLAN {a.vlan_id:<4} | {a.name:<24} | CIDR: {a.cidr:<18} | "
                f"GW: {a.first_usable_gateway:<15} | Usable: {a.usable_hosts:<5} | Eff: {eff}"
            )
        vlans_block = "\n".join(vlan_summary)

        features_str = ", ".join(self.profile.features) if self.profile.features else "Standard L2/L3"

        header = f"""!
! ==============================================================================
!  NETARCHITECT AUTOMATED CISCO IOS PROVISIONING SPECIFICATION
! ==============================================================================
!  Target Profile       : {self.profile.name}
!  Description          : {self.profile.description}
!  Link Distance        : {self.profile.distance_m:.1f} meters ({self.profile.distance_m / 1000.0:.2f} km)
!  Root Allocation CIDR : {self.profile.root_prefix}
!  Engineered Features  : {features_str}
! ------------------------------------------------------------------------------
!  [L1 PHYSICAL MEDIA DECISION]
!  Selected Media       : {self.l1.selected_media}
!  Standard Reference   : {self.l1.standard_reference}
!  Engineering Rationale:
!    {self.l1.rationale}
! ------------------------------------------------------------------------------
!  [L3 VLSM ADDRESS ALLOCATIONS]
{vlans_block}
! ------------------------------------------------------------------------------
!  [L3 ROUTING ARCHITECTURE DECISION]
!  Selected Protocol    : {self.routing.selected_protocol}
!  Topology Scope       : {self.routing.topology_scope}
!  Engineering Rationale:
!    {self.routing.rationale}
! ==============================================================================
!
"""
        return header

    def generate_global_and_l2(self) -> str:
        """Generate global system, Spanning Tree (RSTP), VLANs, Access, and 802.1Q Trunk ports."""
        lines = [
            "version 15.2",
            "service timestamps debug datetime msec",
            "service timestamps log datetime msec",
            "service password-encryption",
            "!",
            f"hostname {self.profile.name.upper()}-CORE-01",
            "!",
            "boot-start-marker",
            "boot-end-marker",
            "!",
            "no ip domain-lookup",
            "ip routing",
            "ip cef",
            "!",
            "! --- LAYER 2 SPANNING TREE (RSTP) ---",
            "spanning-tree mode rapid-pvst",
            "spanning-tree portfast default",
            "spanning-tree portfast bpduguard default",
            "spanning-tree extend system-id",
            "!",
            "! --- 802.1Q VLAN DEFINITIONS ---",
        ]

        vlan_ids = [str(a.vlan_id) for a in self.allocations]
        vlan_list_str = ",".join(vlan_ids)

        for a in self.allocations:
            lines.extend([
                f"vlan {a.vlan_id}",
                f" name {a.name}",
                " state active",
                "!",
            ])

        lines.extend([
            "! --- 802.1Q TRUNK UPLINK INTERFACE ---",
            "interface TenGigabitEthernet0/1/1",
            f" description Uplink Interconnect [{self.l1.selected_media}] - {self.profile.name}",
            " switchport trunk encapsulation dot1q",
            " switchport mode trunk",
            f" switchport trunk allowed vlan {vlan_list_str}",
            " switchport nonegotiate",
            " mtu 9000",
            " no shutdown",
            "!",
        ])

        lines.append("! --- ACCESS PORT TEMPLATES ---")
        port_num = 1
        for a in self.allocations:
            lines.extend([
                f"interface GigabitEthernet1/0/{port_num}",
                f" description Edge Access Port for {a.name} [VLAN {a.vlan_id}]",
                " switchport mode access",
                f" switchport access vlan {a.vlan_id}",
                " spanning-tree portfast",
                " spanning-tree bpduguard enable",
                " no shutdown",
                "!",
            ])
            port_num += 1

        return "\n".join(lines)

    def generate_svis_and_redundancy(self) -> str:
        """Generate Switch Virtual Interfaces (SVIs) with HSRP redundancy when requested."""
        has_hsrp = any("HSRP" in f or "Dual-Homed" in f for f in self.profile.features)
        lines = [
            "! --- LAYER 3 SWITCH VIRTUAL INTERFACES (SVIs) ---",
        ]

        for a in self.allocations:
            lines.extend([
                f"interface Vlan{a.vlan_id}",
                f" description SVI Gateway for {a.name} [{a.cidr}]",
            ])

            if has_hsrp:
                # With HSRP: Physical IP is gateway + 1 or gateway, VIP is first_usable_gateway
                # Assign secondary deterministic physical IP (gateway IP + 1)
                net = ipaddress.IPv4Network(a.cidr)
                phys_ip = str(ipaddress.IPv4Address(a.first_usable_gateway) + 1)
                lines.extend([
                    f" ip address {phys_ip} {a.netmask}",
                    f" standby {a.vlan_id} ip {a.first_usable_gateway}",
                    f" standby {a.vlan_id} priority 110",
                    f" standby {a.vlan_id} preempt",
                    f" standby {a.vlan_id} authentication md5 key-string FinTechHSRP99",
                ])
            else:
                lines.append(f" ip address {a.first_usable_gateway} {a.netmask}")

            lines.extend([
                " no ip redirects",
                " no ip unreachables",
                " no shutdown",
                "!",
            ])

        return "\n".join(lines)

    def generate_qos_and_services(self) -> str:
        """Generate QoS policy maps or IPsec crypto stubs based on profile features."""
        lines = []

        # Sub-5ms QoS for FinTech / Metro MAN
        if any("QoS" in f or "Sub-5ms" in f for f in self.profile.features):
            lines.extend([
                "! --- METRO QoS SUB-5MS STRICT PRIORITY POLICY ---",
                "class-map match-any CRITICAL_TRADING_VOICE",
                " match ip dscp ef",
                " match ip precedence 5",
                "!",
                "class-map match-any INTERACTIVE_VIDEO",
                " match ip dscp af41",
                " match ip dscp af42",
                "!",
                "policy-map POLICY_SUB5MS_CORE",
                " class CRITICAL_TRADING_VOICE",
                "  priority percent 35",
                " class INTERACTIVE_VIDEO",
                "  bandwidth remaining percent 25",
                " class class-default",
                "  fair-queue",
                "  random-detect dscp-based",
                "!",
                "interface TenGigabitEthernet0/1/1",
                " service-policy output POLICY_SUB5MS_CORE",
                "!",
            ])

        # IPsec VPN for Global WAN
        if any("IPsec" in f for f in self.profile.features):
            lines.extend([
                "! --- IPSEC VPN TUNNEL OVERLAY SPECIFICATION ---",
                "crypto isakmp policy 10",
                " encr aes 256",
                " authentication pre-share",
                " group 14",
                " lifetime 86400",
                "!",
                "crypto isakmp key CiscoEnterpriseIPsecSecret100! address 198.51.100.2",
                "!",
                "crypto ipsec transform-set TS_AES256_SHA256 esp-aes 256 esp-sha256-hmac",
                " mode tunnel",
                "!",
                "crypto map WAN_CRYPTO_MAP 10 ipsec-isakmp",
                " set peer 198.51.100.2",
                " set transform-set TS_AES256_SHA256",
                " match address ACL_IPSEC_INTERCONNECT",
                "!",
                "interface Tunnel100",
                " description IPsec VTI to Multi-Cloud VPC Transit Gateway",
                " ip address 172.31.255.1 255.255.255.252",
                " tunnel source TenGigabitEthernet0/1/1",
                " tunnel destination 198.51.100.2",
                " tunnel mode ipsec ipv4",
                " tunnel protection ipsec profile IPSEC_PROFILE_WAN",
                " no shutdown",
                "!",
            ])

        return "\n".join(lines) if lines else ""

    def generate_routing_config(self) -> str:
        """Generate Cisco IOS routing protocol configuration (OSPF / BGP)."""
        lines = []

        if "Single-Area OSPF" in self.routing.selected_protocol:
            lines.extend([
                "! --- L3 ROUTING: SINGLE-AREA OSPFv2 (AREA 0) ---",
                "router ospf 1",
                " router-id 1.1.1.1",
                " log-adjacency-changes detail",
                " auto-cost reference-bandwidth 100000",
                " passive-interface default",
            ])
            # Set SVIs as passive and uplinks as active
            for a in self.allocations:
                lines.append(f" no passive-interface Vlan{a.vlan_id}")
            lines.append(" no passive-interface TenGigabitEthernet0/1/1")

            for a in self.allocations:
                lines.append(f" network {a.network_address} {a.wildcard_mask} area 0")

            lines.append("!")

        else:
            # Hierarchical Multi-Area OSPF + eBGP
            lines.extend([
                "! --- L3 ROUTING: HIERARCHICAL MULTI-AREA OSPF ---",
                "router ospf 1",
                " router-id 10.255.255.1",
                " log-adjacency-changes detail",
                " auto-cost reference-bandwidth 100000",
                " passive-interface default",
            ])
            for a in self.allocations:
                lines.append(f" no passive-interface Vlan{a.vlan_id}")
            lines.append(" no passive-interface TenGigabitEthernet0/1/1")

            # Route summarization if features include summarization or global wan
            has_summarization = any("Summarization" in f or "Supernetting" in f for f in self.profile.features)
            if has_summarization:
                root_net = ipaddress.IPv4Network(self.profile.root_prefix)
                lines.append(f" area 10 range {root_net.network_address} {root_net.netmask}")

            for idx, a in enumerate(self.allocations):
                # Put first 2 in Area 0 (Backbone Core), rest in designated Area 10/20
                assigned_area = 0 if idx < 2 else 10
                lines.append(f" network {a.network_address} {a.wildcard_mask} area {assigned_area}")

            lines.extend([
                "!",
                "! --- L3 ROUTING: BGP INTER-DOMAIN PEERING ---",
                "router bgp 65001",
                " bgp router-id 10.255.255.1",
                " bgp log-neighbor-changes",
                " neighbor 198.51.100.2 remote-as 65500",
                " neighbor 198.51.100.2 description Transit_Cloud_Boundary",
                " !",
                " address-family ipv4",
            ])

            root_net = ipaddress.IPv4Network(self.profile.root_prefix)
            lines.append(f"  network {root_net.network_address} mask {root_net.netmask}")
            lines.extend([
                "  neighbor 198.51.100.2 activate",
                "  neighbor 198.51.100.2 next-hop-self",
                " exit-address-family",
                "!",
            ])

        return "\n".join(lines)

    def generate_security_acls(self) -> str:
        """Generate standard security ACLs permitting allocated subnets."""
        lines = [
            "! --- SECURITY ACCESS CONTROL LISTS (ACLs) ---",
            "ip access-list standard ACL_PERMIT_INTERNAL_SUBNETS",
            " remark Deterministic ACL: Permit all algorithmically allocated subnets",
        ]

        for a in self.allocations:
            lines.append(
                f" permit {a.network_address} {a.wildcard_mask} log  ! {a.name} [VLAN {a.vlan_id}]"
            )

        lines.extend([
            " deny any log",
            "!",
        ])

        # If IPsec is in features, add crypto ACL
        if any("IPsec" in f for f in self.profile.features):
            lines.extend([
                "ip access-list extended ACL_IPSEC_INTERCONNECT",
                " remark Permit IPsec overlay between enterprise root and remote VPC",
            ])
            root_net = ipaddress.IPv4Network(self.profile.root_prefix)
            lines.extend([
                f" permit ip {root_net.network_address} {root_net.hostmask} 10.200.0.0 0.0.255.255",
                " deny ip any any log",
                "!",
            ])

        lines.extend([
            "line con 0",
            " exec-timeout 15 0",
            " logging synchronous",
            "line vty 0 4",
            " access-class ACL_PERMIT_INTERNAL_SUBNETS in",
            " exec-timeout 15 0",
            " transport input ssh",
            " logging synchronous",
            "!",
            "end",
        ])

        return "\n".join(lines)

    def generate_full_config(self) -> str:
        """Compose the complete, copy-paste ready Cisco IOS configuration file."""
        sections = [
            self.generate_header(),
            self.generate_global_and_l2(),
            self.generate_svis_and_redundancy(),
        ]
        qos_sec = self.generate_qos_and_services()
        if qos_sec:
            sections.append(qos_sec)

        sections.append(self.generate_routing_config())
        sections.append(self.generate_security_acls())

        return "\n".join(sections)
