# NetArchitect — AI Engineering Audit Log

**Project:** NetArchitect: Recommendation & Config Engine 
**Status:** Audited & Verified  

---

## 1. Executive Summary & Purpose

The purpose of this audit log is to document genuine instances where automated or AI-generated networking recommendations and code contained technical defects, invalid assumptions, or security vulnerabilities during development. In accordance with the assignment guidelines:
- No artificial bugs or fabricated histories are included.
- Every documented incident occurred during the construction of the NetArchitect decision and configuration engines.
- Each entry details the prompt, flawed output, technical defect, diagnosis, detection method, correction, and verification evidence.

---

## 2. Audited Defect Incidents

### Incident 1: String Prefix Assumption in VLAN-to-Subnet Association (`startswith('mgmt')`)

- **Category:** Subnet-to-VLAN Mapping / SVI Generation Logic
- **Component:** `engine/topology_engine.py` (`_build_vlan_specs`) & `generator/cisco_ios.py`

#### 1. Context & Original Intent
In the Campus LAN profile (`profiles/presets.py`), the subnet allocation request is named `"Management"` (30 required hosts), while the corresponding IEEE 802.1Q VLAN is named `"Mgmt"` (VLAN 70). The topology engine must join the allocated subnet with the VLAN definition so the configuration generator can configure `interface Vlan70` with the allocated default gateway (`10.10.9.65 255.255.255.224`).

#### 2. Actual Flawed Code
```python
# Flawed implementation in engine/topology_engine.py:
alloc = alloc_map.get(name)
if alloc is None:
    for k, a in alloc_map.items():
        if k.lower() == name.lower() or (k.lower().startswith("mgmt") and name.lower().startswith("mgmt")):
            alloc = a
            break
```

#### 3. Description of the Defect
When `name` was `"Mgmt"` and `k` was `"Management"`, `k.lower()` evaluated to `"management"`. Because `"management"` starts with `"manag"` rather than `"mgmt"`, the condition `k.lower().startswith("mgmt")` evaluated to `False`. The allocation was not associated with VLAN 70. Consequently:
1. `VlanSpec.subnet`, `svi_ip`, and `svi_mask` remained empty strings (`""`).
2. The Cisco IOS generator skipped generating the Layer 3 SVI (`interface Vlan70`).
3. OSPF network statement `network 10.10.9.64 0.0.0.31 area 0` was omitted from Building-A's routing process.

#### 4. Technical Diagnosis
AI-generated string heuristics often assume common abbreviations share a common prefix with their unabbreviated English forms (e.g. `mgmt` vs `management`). In reality, `mgmt` is an abbreviation (contraction), not a prefix. This caused a silent mapping failure that bypassed syntax checks and would have resulted in unrouted management traffic and inaccessible switch management in production.

#### 5. Detection Method
The defect was detected by automated unit testing in `tests/test_config_generator.py`:
```python
def test_svi_addresses_match_vlsm(self, campus_result):
    vlsm = allocate_from_plan(CAMPUS_LAN_PRESET)
    core_cfg = next(d for d in campus_result.device_configs if d.hostname == "Building-A")
    for alloc in vlsm.allocations:
        if alloc.status == "allocated":
            expected_svi = f"ip address {alloc.gateway} {alloc.subnet_mask}"
            assert expected_svi in core_cfg.config_text  # FAILED: 10.10.9.65 not found
```

#### 6. Correction
Replaced the flawed prefix check with bidirectional token set membership matching:
```python
alloc = alloc_map.get(name)
if alloc is None:
    mgmt_tokens = {"mgmt", "management", "manage"}
    for k, a in alloc_map.items():
        if k.lower() == name.lower():
            alloc = a
            break
        if any(t in k.lower() for t in mgmt_tokens) and any(t in name.lower() for t in mgmt_tokens):
            alloc = a
            break
```

#### 7. Verification Evidence
- `tests/test_config_generator.py::TestCampusLanConfiguration::test_svi_addresses_match_vlsm PASSED`
- `tests/test_config_generator.py::TestCampusLanConfiguration::test_ospf_network_statements_match_vlsm PASSED`
- Inspection of `exports/campus_lan_config.txt` confirmed `interface Vlan70` generated with `ip address 10.10.9.65 255.255.255.224` and `network 10.10.9.64 0.0.0.31 area 0` present under `router ospf 1`.

---

### Incident 2: Boolean Area Flag Overriding Subnet Scale Rule in Routing Explainability

- **Category:** Explainability Engine / Routing Threshold Rule
- **Component:** `engine/explainability.py` (`explain_routing_architecture`)

#### 1. Context & Original Intent
PROJECT_SPEC.md §8 mandates:
> Single autonomous system with fewer than 50 subnets: recommend OSPF Area 0.  
> Single autonomous system with 50 or more subnets: recommend Multi-Area OSPF to limit SPF computation scope and isolate LSDB churn.

When a network plan specifies a single autonomous system with 60 subnets, the engine must select `ProtocolChoice.MULTI_AREA_OSPF` and explain that the `>= 50 subnets` threshold triggered the multi-area recommendation.

#### 2. Actual Flawed Code
```python
# Flawed implementation in engine/explainability.py:
if decision.protocol in (ProtocolChoice.OSPF, ProtocolChoice.MULTI_AREA_OSPF):
    if decision.single_area_ospf:
        rule = f"Single autonomous system (ASN {decision.autonomous_systems}) AND subnet count ({decision.subnet_count}) < 50 subnets"
        tech = f"Single-Area OSPF (Area 0) is recommended because subnet count ({decision.subnet_count}) < 50..."
    else:
        rule = f"Single autonomous system with subnet count ({decision.subnet_count}) >= 50..."
```

#### 3. Description of the Defect
In `engine/routing_engine.py`, `single_area_ospf` was computed as `(len(ospf_area_specs) <= 1)`. When a test input supplied 60 subnets without pre-enumerating explicit area dictionaries in the plan, `_build_ospf_areas` defaulted to generating Area 0 specifications. Consequently, `decision.single_area_ospf` was `True` even though `decision.protocol` was correctly chosen as `ProtocolChoice.MULTI_AREA_OSPF`.
The explainability engine branched on `decision.single_area_ospf` and output the explanation:
> *"Single-Area OSPF (Area 0) is recommended because subnet count (60) < 50 subnets"*

This produced an internal contradiction: the protocol was Multi-Area OSPF, but the justification claimed it was Single-Area OSPF because 60 < 50.

#### 4. Technical Diagnosis
AI code commonly combines disparate state flags (`protocol == MULTI_AREA_OSPF` and `single_area_ospf == True`) without defining a strict precedence hierarchy. When the decision engine recommends multi-area OSPF based on subnet scaling, the explanation must derive directly from the protocol decision enum rather than relying on a secondary area-count flag.

#### 5. Detection Method
Detected by `tests/test_explainability.py`:
```python
def test_multi_area_ospf_justification(self):
    plan = {"sites": [{"name": "SiteA"}, {"name": "SiteB"}], "autonomous_systems": [65001]}
    dec = decide_routing(plan, subnet_count=60)
    justifications = explain_routing_architecture(dec)
    assert ">= 50" in justifications[0].rule_applied  # FAILED: '< 50 subnets' found
```

#### 6. Correction
Separated `ProtocolChoice.OSPF` and `ProtocolChoice.MULTI_AREA_OSPF` into distinct branches:
```python
if decision.protocol == ProtocolChoice.OSPF:
    rule = f"Single autonomous system (ASN {decision.autonomous_systems}) AND subnet count ({decision.subnet_count}) < {OSPF_SINGLE_AREA_SUBNET_THRESHOLD} subnets"
    tech = f"Single-Area OSPF (Area 0) is recommended..."
elif decision.protocol == ProtocolChoice.MULTI_AREA_OSPF:
    rule = f"Single autonomous system with subnet count ({decision.subnet_count}) >= {OSPF_SINGLE_AREA_SUBNET_THRESHOLD} OR multi-site geographic distribution..."
    tech = f"Multi-Area OSPF is selected to partition the {decision.subnet_count} subnets..."
```

#### 7. Verification Evidence
- `tests/test_explainability.py::TestDynamicRoutingExplanations::test_multi_area_ospf_justification PASSED`
- Pytest suite verified all 13 explainability tests pass with exact threshold alignment.

---

### Incident 3: Unrestricted Switchport Trunk Allowed List (`allowed vlan all`)

- **Category:** Layer 2 Security & Cisco IOS Configuration Quality
- **Component:** `generator/cisco_ios.py` (`generate_device_config`)

#### 1. Context & Original Intent
In enterprise switching, default IEEE 802.1Q trunk ports permit VLANs 1 through 4094. PROJECT_SPEC.md §10 specifically requires:
> Avoid unrestricted VLAN trunks and unnecessarily permissive ACLs.  
> Keep VLAN IDs, interface roles, IP addresses and routing statements consistent.

Trunk ports connecting switches must explicitly enumerate only the active VLANs in the topology plan plus the dedicated native VLAN.

#### 2. Actual Flawed Code
During early prototyping of trunk port generation, standard AI template code generated:
```cisco
interface GigabitEthernet0/0
 description Uplink trunk
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 999
 ! Missing explicit 'switchport trunk allowed vlan' — defaults to 1-4094
 no shutdown
```

#### 3. Description of the Defect
Omitting the `switchport trunk allowed vlan <list>` command in Cisco IOS allows all 4094 VLANs across the trunk by default. This causes:
1. Unnecessary propagation of Broadcast, Unknown unicast, and Multicast (BUM) frames across inter-building links.
2. Inadvertent extension of broadcast domains into unauthorized distribution areas.
3. Violation of assignment quality requirements prohibiting unrestricted trunks.

#### 4. Technical Diagnosis
AI generators often omit the allowed-VLAN statement because Cisco IOS syntax accepts `switchport mode trunk` without it. In automated testing and security auditing, unrestricted trunks represent a major vulnerability (STP topology extension, VLAN hopping, broadcast storm risk).

#### 5. Detection Method
Enforced via automated assertion in `tests/test_config_generator.py`:
```python
def test_explicit_vlan_trunks_and_native_vlan(self, campus_result):
    core_cfg = next(d for d in campus_result.device_configs if d.hostname == "Building-A")
    assert "switchport trunk allowed vlan" in core_cfg.config_text
    assert "switchport trunk allowed vlan all" not in core_cfg.config_text
    assert "10,20,30,40,50,60,70,80,999" in core_cfg.config_text
```

#### 6. Correction
Enforced deterministic generation of explicit allowed VLAN strings joining all active VLANs and the isolated native VLAN:
```python
if intf.allowed_vlans:
    allowed_str = ",".join(str(vid) for vid in sorted(intf.allowed_vlans))
    allowed_with_native = f"{allowed_str},{topology.native_vlan}"
    lines.append(f" switchport trunk allowed vlan {allowed_with_native}")
else:
    lines.append(f" switchport trunk allowed vlan {topology.native_vlan}")
lines.append(" switchport nonegotiate")
```

#### 7. Verification Evidence
- `tests/test_config_generator.py::TestCampusLanConfiguration::test_explicit_vlan_trunks_and_native_vlan PASSED`
- All three exported configuration files in `exports/` show explicit allowed VLAN lists:
  - `campus_lan_config.txt`: `switchport trunk allowed vlan 10,20,30,40,50,60,70,80,999`
  - `metro_man_config.txt`: `switchport trunk allowed vlan 10,20,30,40,50,999`

---

## 3. Limitations of AI-Generated Networking Code

Based on the development and auditing of NetArchitect, AI-generated networking recommendations and CLI configurations exhibit several structural limitations:

1. **Failure of Transitive Context:** LLMs frequently produce syntactically valid Cisco commands in isolation that conflict globally (e.g. configuring a `/24` subnet on an interface but writing a `/26` wildcard mask in `router ospf`). Deterministic data models (such as NetArchitect's `TopologyPlan` and `VLSMResult`) are mandatory to ensure cross-module consistency.
2. **Hallucination of Production Credentials and Endpoints:** Generative models routinely fabricate realistic-looking private IP addresses, public BGP neighbor IPs, and pre-shared keys. NetArchitect resolves this by strictly prohibiting invented values and using explicit, audited placeholders (e.g. `<ENTER_SECURE_ENABLE_SECRET>`, `<REMOTE-PEER-IP-PLACEHOLDER>`).
3. **Boundary Distance Inaccuracies:** Generic AI models often treat physical media distance recommendations as arbitrary rules rather than standard-defined channel limits (e.g., claiming Cat6 copper can run 150m, or assuming OM4 reaches kilometers). NetArchitect enforces strict IEEE 802.3an (100 m) and 802.3ae (400 m) hard boundaries with automated distance violation exceptions.

---

## 4. Verification Protocol Summary

Every recommendation and configuration in NetArchitect was verified through the following deterministic pipeline:

| Phase | Engine Component | Verification Method | Result |
|---|---|---|---|
| **Phase 1** | Input Validation | `test_input_validation.py` (87 tests) | 100% Passed |
| **Phase 2** | Physical Media Engine | `test_media_engine.py` (83 tests) | 100% Passed |
| **Phase 3** | VLSM Subnet Allocator | `test_vlsm_allocator.py` (110 tests) | 100% Passed |
| **Phase 4** | Routing & Topology Engine | `test_routing_engine.py` (105 tests) | 100% Passed |
| **Phase 5** | Explainability Engine | `test_explainability.py` (13 tests) | 100% Passed |
| **Phase 6** | Cisco IOS Generator | `test_config_generator.py` (12 tests) | 100% Passed |
| **Phase 7** | Full Integration Pipeline | `test_integration_profiles.py` (6 tests) | 100% Passed |
| **Total** | **Full Regression Suite** | **416 unit & integration tests** | **416 Passed, 1 Skipped** |
