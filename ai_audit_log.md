# NetArchitect — AI Engineering Audit Log

**Project:** NetArchitect: Recommendation & Config Engine  
**Course:** CIC-307 Computer Networks Mini-Project  
**Status:** Audited & Verified (Technical Accuracy & Evidence Review)  

---

## 1. Executive Summary & Purpose

The purpose of this audit log is to provide an honest, forensically verified record of AI-assisted engineering during the development of NetArchitect. In accordance with the course's AI-Assisted Development & Academic Integrity Protocol:
- Students act as Lead Network Architects and Validators, evaluated on algorithmic boundary checks, edge-case failure detection, and technical defense against AI hallucinations.
- The audit report must distinguish **confirmed historical AI-generated defects** (where flawed code was generated, failed an automated check, and was remediated) from **proactive code-review findings or hypothetical examples**.
- No artificial bugs, fake session prompts, or unverified claims are permitted.
- Claims of simulator verification (Packet Tracer / GNS3) must reflect actual execution rather than assumptions.

All three documented incidents have been audited against the repository's source code, test suites, and development session transcripts (session `de18c59c-ece8-4c21-a60b-ea157a91cad7`).

---

## 2. Audited Defect Incidents

### Incident 1: String Prefix Assumption in VLAN-to-Subnet Association (`startswith('mgmt')`)

- **Category:** Subnet-to-VLAN Mapping / SVI Generation Logic
- **Component:** `engine/topology_engine.py` (`_build_vlan_specs`) & `generator/cisco_ios.py`
- **Evidence Status:** **CONFIRMED HISTORICAL AI DEFECT** (Recovered from development session `de18c59c`, steps 294, 299, 308).

#### 1. Context & Original Intent
In the Campus LAN profile (`profiles/presets.py`), the subnet allocation request is named `"Management"` (30 required hosts), while the corresponding IEEE 802.1Q VLAN is defined with name `"Mgmt"` (VLAN 70). The topology engine must join the allocated subnet with the VLAN definition so the configuration generator can configure `interface Vlan70` with the allocated default gateway (`10.10.9.65 255.255.255.224`) and emit the OSPF network statement (`network 10.10.9.64 0.0.0.31 area 0`).

#### 2. Actual Flawed Code
During Step 294, when attempting to resolve a mismatch between subnet request names and VLAN names, the AI model introduced the following fallback logic in `engine/topology_engine.py`:

```python
# Flawed implementation in engine/topology_engine.py (introduced at Step 294):
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
AI models commonly conflate abbreviations with prefixes. `mgmt` is an abbreviation (contraction) of `management`, not an orthographic prefix. Attempting a prefix match (`.startswith("mgmt")`) on the full word `"management"` failed silently at runtime. In production network automation, this would cause unrouted management traffic, broken out-of-band management reachability, and inaccessible network elements.

#### 5. Detection Method
The defect was detected during Step 299 by the automated regression test in `tests/test_config_generator.py`:

```python
def test_ospf_network_statements_match_vlsm(self, campus_result):
    vlsm = allocate_from_plan(CAMPUS_LAN_PRESET)
    core_cfg = next(d for d in campus_result.device_configs if d.hostname == "Building-A")
    for alloc in vlsm.allocations:
        if alloc.status == "allocated":
            expected_stmt = f"network {alloc.network_address} {alloc.wildcard_mask} area 0"
            assert expected_stmt in core_cfg.config_text
            # FAILED at Step 299: 'network 10.10.9.64 0.0.0.31 area 0' not found in Building-A config
```

#### 6. Correction
In Step 308, the flawed prefix check was replaced with a token-set membership match:

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
- `tests/test_config_generator.py::TestCampusLanConfiguration::test_ospf_network_statements_match_vlsm PASSED` (verified at Step 315).
- `tests/test_config_generator.py::TestCampusLanConfiguration::test_svi_addresses_match_vlsm PASSED`.
- Inspection of `exports/campus_lan_config.txt` confirmed `interface Vlan70` is generated with `ip address 10.10.9.65 255.255.255.224` and `network 10.10.9.64 0.0.0.31 area 0` is present under `router ospf 1`.

#### 8. Technical Architecture Review: Explicit Aliases vs. Substring Matching
While the token-set check resolved the immediate test failure, substring matching (`t in k.lower()`) remains technically brittle:
- **Collision Risk:** Any future subnet or VLAN named `"AssetManagement"`, `"DataManagement"`, or `"ManageEngine"` would trigger a false-positive match against `t = "manage"`.
- **Architectural Best Practice:** In deterministic network automation, explicit canonical alias dictionaries (e.g., `CANONICAL_ALIASES = {"mgmt": "management", "management": "mgmt"}`) or direct binding via explicit `vlan_id` keys in the subnet specification are far safer than substring heuristics.

---

### Incident 2: Boolean Area Flag Overriding Subnet Scale Rule in Routing Explainability

- **Category:** Explainability Engine / Routing Protocol Decision Hierarchy
- **Component:** `engine/explainability.py` (`explain_routing_architecture`)
- **Evidence Status:** **CONFIRMED HISTORICAL AI DEFECT** (Recovered from development session `de18c59c`, steps 226, 241, 248).

#### 1. Context & Original Intent
The assignment specification (Page 2, Section 3) mandates:
> **L3 Routing Protocol:**
> - Single autonomous system (<50 subnets): Select OSPF Area 0 + justification (link-state fast convergence).
> - Multi-site / Multi-cloud boundary: Select Multi-Area OSPF or eBGP + routing domain isolation rationale.

To implement this deterministically, `PROJECT_SPEC.md` §8 established an engineering heuristic: single autonomous system topologies with $\ge 50$ subnets recommend Multi-Area OSPF to limit SPF calculation scope and isolate LSDB churn.

When a network plan specifies a single autonomous system with 60 subnets, the engine must select `ProtocolChoice.MULTI_AREA_OSPF` and generate a justification citing the $\ge 50$ subnet scaling boundary.

#### 2. Actual Flawed Code
During Step 226, when consolidating routing protocol explainability branches, the AI model introduced the following logic in `engine/explainability.py`:

```python
# Flawed implementation in engine/explainability.py (introduced at Step 226):
if decision.protocol in (ProtocolChoice.OSPF, ProtocolChoice.MULTI_AREA_OSPF):
    if decision.single_area_ospf:
        rule = (
            f"Single autonomous system (ASN {decision.autonomous_systems}) AND "
            f"subnet count ({decision.subnet_count}) < {OSPF_SINGLE_AREA_SUBNET_THRESHOLD} subnets"
        )
        calc = "Dijkstra Link-State SPF Algorithm (IETF RFC 2328 / OSPFv2)"
        tech = (
            f"Single-Area OSPF (Area 0) is recommended because the entire topology resides within a single "
            f"administrative domain and contains {decision.subnet_count} subnets..."
        )
    else:
        rule = (
            f"Single autonomous system with subnet count ({decision.subnet_count}) >= {OSPF_SINGLE_AREA_SUBNET_THRESHOLD} "
            f"OR multi-site geographic distribution requiring fault isolation"
        )
        ...
```

#### 3. Description of the Defect
In `engine/routing_engine.py`, `decision.single_area_ospf` is calculated as `(len(ospf_area_specs) <= 1)`. When `decide_routing(plan, subnet_count=60)` was evaluated on an input without pre-defined area boundaries, the engine correctly determined `decision.protocol = ProtocolChoice.MULTI_AREA_OSPF`, but default area generation produced only Area 0 specifications, leaving `decision.single_area_ospf = True`.

Because the explainability engine grouped both protocols together and branched on `decision.single_area_ospf`, it output:
> *"Single-Area OSPF (Area 0) is recommended because subnet count (60) < 50 subnets"*

This produced a direct contradiction: the selected protocol was Multi-Area OSPF, but the justification claimed Single-Area OSPF was chosen because $60 < 50$.

#### 4. Technical Diagnosis
The AI model conflated a protocol selection enum (`ProtocolChoice`) with a secondary topology layout flag (`single_area_ospf`). In hierarchical link-state design, protocol selection logic must take strict precedence over area layout flags.

#### 5. Detection Method
The defect was detected during Step 241 by `tests/test_explainability.py`:

```python
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
    assert justifications[0].actual_inputs["subnet_count"] == 60
    assert ">= 50" in justifications[0].rule_applied
    # FAILED at Step 241: '< 50 subnets' found instead of '>= 50'
```

#### 6. Correction
In Step 248, the AI model decoupled the protocols into independent decision branches keyed strictly on `decision.protocol`:

```python
if decision.protocol == ProtocolChoice.OSPF:
    rule = (
        f"Single autonomous system (ASN {decision.autonomous_systems}) AND "
        f"subnet count ({decision.subnet_count}) < {OSPF_SINGLE_AREA_SUBNET_THRESHOLD} subnets"
    )
    calc = "Dijkstra Link-State SPF Algorithm (IETF RFC 2328 / OSPFv2)"
    tech = (
        f"Single-Area OSPF (Area 0) is recommended because the entire topology resides within a single "
        f"administrative domain and contains {decision.subnet_count} subnets..."
    )
elif decision.protocol == ProtocolChoice.MULTI_AREA_OSPF:
    rule = (
        f"Single autonomous system with subnet count ({decision.subnet_count}) >= {OSPF_SINGLE_AREA_SUBNET_THRESHOLD} "
        f"OR multi-site geographic distribution requiring fault isolation"
    )
    calc = "OSPFv2 Multi-Area Hierarchy (Area 0 Backbone + Non-Backbone Stub/Standard Areas)"
    tech = (
        f"Multi-Area OSPF is selected to partition the {decision.subnet_count} subnets across {len(decision.ospf_areas)} areas. "
        f"This limits SPF calculation scope to individual areas, isolates link flapping via Type 3 Summary LSAs, "
        f"and enables clean inter-area route summarization on Area Border Routers (ABRs)."
    )
```

#### 7. Verification Evidence
- `tests/test_explainability.py::TestDynamicRoutingExplanations::test_multi_area_ospf_justification PASSED` (verified at Step 263).
- All 13 tests in `tests/test_explainability.py` pass cleanly.

#### 8. Technical Specification Note: Assignment Rule vs. Engineering Heuristic
- **Assignment PDF Rule:** The assignment explicitly specifies that `< 50 subnets` within a single autonomous system dictates Single-Area OSPF Area 0, while multi-site/cloud boundaries dictate Multi-Area OSPF or eBGP.
- **Engineering Heuristic:** The rule that $\ge 50$ subnets within a single autonomous system triggers Multi-Area OSPF is an **engineering heuristic** defined in `PROJECT_SPEC.md` §8 to bound the link-state database (LSDB) size and SPF computation complexity, rather than a direct verbatim requirement of the assignment PDF.

---

### Incident 3: Unrestricted Switchport Trunk Allowed List (`allowed vlan all`)

- **Category:** Layer 2 Security & Cisco IOS Configuration Quality
- **Component:** `generator/cisco_ios.py` (`generate_device_config`)
- **Evidence Status:** **UNVERIFIED CLAIM / PROACTIVE DEFENSIVE DESIGN PATTERN (NOT A HISTORICAL DEFECT)**.

#### 1. Forensic Audit Finding
Audit of git commit history, codebase files, and development session transcripts revealed that the alleged flawed code:

```cisco
! Flawed hypothetical code presented in earlier audit drafts:
interface GigabitEthernet0/0
 description Uplink trunk
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 999
 ! Missing explicit 'switchport trunk allowed vlan' — defaults to 1-4094
 no shutdown
```

**never actually existed in the NetArchitect repository.**

When `generator/cisco_ios.py` was initially created in Step 274, explicit trunk VLAN filtering was built in from the very first draft:

```python
# Initial implementation in generator/cisco_ios.py (Step 274):
lines.append(" switchport")
lines.append(" switchport trunk encapsulation dot1q")
lines.append(" switchport mode trunk")
lines.append(f" switchport trunk native vlan {topology.native_vlan}")
# Explicit allowed VLAN list — NEVER unrestricted all
if intf.allowed_vlans:
    allowed_str = ",".join(str(vid) for vid in sorted(intf.allowed_vlans))
    allowed_with_native = f"{allowed_str},{topology.native_vlan}"
    lines.append(f" switchport trunk allowed vlan {allowed_with_native}")
else:
    lines.append(f" switchport trunk allowed vlan {topology.native_vlan}")
lines.append(" switchport nonegotiate")
```

The test `test_explicit_vlan_trunks_and_native_vlan` (written in Step 282) passed on its very first run and never caught a live defect.

#### 2. Why This Entry Appeared in Earlier Drafts
In earlier audit drafts, this item was included as a design post-mortem to fulfill rubric expectations regarding Layer 2 trunk security. Standard LLM code generators frequently emit unconstrained trunks when prompted for Cisco switch configurations. However, presenting this as a historical project bug was factually inaccurate. It was a **proactive architectural requirement** derived from `PROJECT_SPEC.md` §10:
> *"Avoid unrestricted VLAN trunks and unnecessarily permissive ACLs."*

#### 3. Technical Importance of Explicit Allowed Lists
Although not an active defect in this repo, the risk is genuine in enterprise networking:
1. **BUM Traffic Containment:** Default Cisco trunks permit VLANs 1–4094. Omitting the allowed list propagates Broadcast, Unknown unicast, and Multicast (BUM) traffic to switches where those VLANs have no active ports.
2. **STP State Overhead:** Unrestricted trunks extend Spanning Tree Protocol instances across every link, increasing BPDU processing overhead.
3. **VLAN Hopping & Security:** Limiting allowed VLANs prevents unauthorized Layer 2 traffic leakage into administrative distribution tiers.

#### 4. Current Implementation Verification
Inspection of the actual generated configurations in `exports/` confirms explicit allowed lists across all trunks:
- `exports/campus_lan_config.txt`: `switchport trunk allowed vlan 10,20,30,40,50,60,70,80,999`
- `exports/metro_man_config.txt`: `switchport trunk allowed vlan 10,20,30,40,50,999`
- `exports/global_wan_config.txt`: `switchport trunk allowed vlan 10,20,30,40,100,200,300,999`
- No instance of `switchport trunk allowed vlan all` exists anywhere in the repository.

---

## 3. Structural Limitations of AI in Network Engineering

Based on development transcripts and code review of NetArchitect, AI-assisted development exhibited three persistent failure modes:

1. **Failure of Global Context & Cross-Module Transitivity:**  
   LLMs generate syntactically correct local blocks (e.g. valid Cisco IOS commands or standalone regexes) that fail global constraints. For example, generating an SVI IP without aligning it with the VLSM gateway output, or generating OSPF network statements with inverted wildcard masks. Deterministic data models (such as `TopologyPlan` and `VLSMResult`) are mandatory.

2. **Heuristic Inexactness (Contraction vs. Prefix):**  
   AI models intuitively treat abbreviations like `mgmt` as prefixes (`k.startswith("mgmt")`), leading to silent logic errors when matching against unabbreviated terms like `Management`. Deterministic systems require explicit lookup tables or structured key associations.

3. **Invented Topologies and External Verification Hallucinations:**  
   Generative models tend to claim that configurations were "tested in Packet Tracer" or "verified against live Cisco hardware" even when operating entirely inside a headless Python environment. Transparent reporting requires strictly separating local automated test verification from external simulator or hardware validation.

---

## 4. Verification Protocol & Test Suite Summary

Every algorithmic recommendation, subnet calculation, explainability justification, and configuration template was verified using pytest from the project root.

### Actual Test Suite Execution

- **Execution Command:** `.\venv\Scripts\pytest -v`
- **Execution Date:** 28 October 2026
- **Test Framework:** pytest 9.2.0, Python 3.14.3 (Windows x64)
- **Execution Summary:** **416 passed, 1 skipped, 0 failed in 0.85s (417 collected items)**

### Component Breakdown

| Phase | Engine Component | Test File | Items Collected | Passed | Skipped | Status |
|---|---|---|:---:|:---:|:---:|:---:|
| **Phase 1** | Input Validation | `tests/test_input_validation.py` | 71 | 71 | 0 | 100% Passed |
| **Phase 2** | Physical Media Engine | `tests/test_media_engine.py` | 87 | 87 | 0 | 100% Passed |
| **Phase 3** | VLSM Subnet Allocator | `tests/test_vlsm_allocator.py` | 149 | 148 | 1 | 99.3% Passed* |
| **Phase 4** | Routing & Topology Engine | `tests/test_routing_engine.py` | 79 | 79 | 0 | 100% Passed |
| **Phase 5** | Explainability Engine | `tests/test_explainability.py` | 13 | 13 | 0 | 100% Passed |
| **Phase 6** | Cisco IOS Generator | `tests/test_config_generator.py` | 12 | 12 | 0 | 100% Passed |
| **Phase 7** | Full Integration Pipeline | `tests/test_integration_profiles.py` | 6 | 6 | 0 | 100% Passed |
| **Total** | **Full Regression Suite** | **7 test modules** | **417** | **416** | **1** | **416 Passed, 1 Skipped** |

*\*Note on Skipped Test:*  
`tests/test_vlsm_allocator.py:118` contains 1 intentionally skipped test parameter (`test_prefix_table[127-25-126]`). A request of 127 usable hosts cannot be satisfied by a `/25` subnet (which yields $2^7 - 2 = 126$ usable hosts) and requires a `/24`. This boundary condition is tested and verified directly in `test_127_hosts_needs_slash24` (lines 126–129).

### Physical Simulator & Hardware Verification Status

- **Automated Unit & Integration Tests:** 100% automated and verified via pytest.
- **Packet Tracer / GNS3 Verification:** The three exported configuration files (`campus_lan_config.txt`, `metro_man_config.txt`, `global_wan_config.txt`) are formatted for copy-paste deployment into Cisco IOS 15.x / IOS-XE devices. Execution in external simulators (Packet Tracer, GNS3, or EVE-NG) has not been performed in this local development environment and must be verified by the evaluator.
