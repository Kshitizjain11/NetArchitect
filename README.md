# NetArchitect: Recommendation & Config Engine

**CIC-307 Computer Networks Mini-Project**  
*Deterministic Network Planning, VLSM Allocation, Explainability & Cisco IOS Configuration Engine*

---

## 1. Overview

**NetArchitect** is an automated, deterministic network engineering planning tool designed to solve structured campus, metropolitan, and wide-area network design tasks. Unlike generic AI scripts, NetArchitect uses first-principles networking calculations based strictly on IEEE 802.3 Ethernet standards, IETF RFCs (including RFC 791, RFC 2328, RFC 4271, and RFC 7296), and Cisco IOS best practices.

### Key Capabilities
- **Deterministic Physical Media Decision Engine:** Evaluates link distances and bandwidth against IEEE channel limits (Cat6a copper ≤ 100 m, OM4 multimode fiber 101–400 m, OS2 single-mode fiber > 400 m), raising explicit distance violations when copper is requested beyond 100 m.
- **VLSM Subnet Allocator:** Performs descending host-count allocation from a root IPv4 prefix without fragmentation, calculating subnet masks, wildcard masks, default gateways (`network + 1`), usable host ranges, and broadcast addresses.
- **Hierarchical Routing & Topology Engine:** Evaluates autonomous system boundaries and subnet scaling (< 50 subnets → Single-Area OSPF Area 0; ≥ 50 subnets → Multi-Area OSPF; Multi-AS / Cloud → eBGP / Hybrid). Models STP bridge priorities (4096 primary root, 8192 backup root), VLAN pruning, Metro EVPL QoS, and Global WAN IPsec VPN tunnels.
- **Contextual Explainability Engine:** Generates comprehensive 6-point engineering justifications for every recommendation (selected result, actual inputs, rule applied, calculation/standard, technical reason, and limitations).
- **Cisco IOS Configuration Generator:** Produces syntax-validated, device-separated Cisco CLI configuration text with explicit allowed VLAN lists, isolated native VLANs (999), and structured placeholders.

---

## 2. Prerequisites & Environment Setup

- **Operating System:** Windows, macOS, or Linux
- **Python:** Python 3.10, 3.11, 3.12, 3.13, or 3.14
- **Package Manager:** `pip`

### Installation

1. Clone or extract the repository:
   ```bash
   cd netarchitect
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *Note on Windows:* If using the Python Launcher, use:
   ```powershell
   py -m pip install -r requirements.txt
   ```

Dependencies specified in `requirements.txt`:
- `streamlit>=1.32.0` (Web user interface)
- `pytest>=8.0.0` (Automated testing suite)
- `pandas` (Tabular data rendering)

---

## 3. Launching the Web Interface

Launch the local Streamlit dashboard:

```bash
streamlit run app.py
```
Or on Windows with `py`:
```powershell
py -m streamlit run app.py
```

The application will start locally at `http://localhost:8501`.

---

## 4. How to Select & Run Profiles

The dashboard sidebar provides instant preset selection for the three mandatory assignment profiles:

1. **Profile A: Campus LAN**
   - Three-building enterprise campus with inter-building links (< 400 m).
   - ~1,600 endpoints across 8 VLANs, PoE APs, RSTP root bridge placement (4096 on Building A, 8192 on Building B), and single-area OSPF (Area 0).
2. **Profile B: Metro MAN**
   - FinTech headquarters connected to two remote branch sites via 15 km and 22 km EVPL circuits over OS2 single-mode fiber.
   - Differentiated Services QoS: Voice (DSCP EF / LLQ 20%), Video (DSCP AF41 / 25%), and Critical Data (DSCP AF21 / 30%) with Fair-Queuing for default traffic.
3. **Profile C: Global WAN**
   - Four metropolitan hub/spoke sites (Mumbai, Delhi, Bangalore, Chennai in AS 65001) plus a cloud VPC (AS 65002) and IoT fleet.
   - Hierarchical Multi-Area OSPF + eBGP peering at ASBR border routers, route summarization, and IKEv2 / IPsec site-to-site VPN tunnels (AES-256 / SHA-256 / DH Group 14).

### Custom Scenarios
Select **"Custom Scenario"** in the sidebar to define custom root IPv4 networks, add custom sites, customize link distances, or supply specific host requirements.

---

## 5. Running Automated Tests

NetArchitect includes an extensive automated test suite covering all modules from unit tests to end-to-end integration:

```bash
pytest tests/ -v
```
Or on Windows:
```powershell
py -m pytest tests/ -v
```

### Test Suite Structure
- `tests/test_input_validation.py`: (87 tests) Parameter ranges, missing fields, invalid CIDR, scenario validation.
- `tests/test_media_engine.py`: (83 tests) 100m, 101m, 400m, 401m boundaries, copper violations, transceivers.
- `tests/test_vlsm_allocator.py`: (110 tests) Descending allocation, masks, wildcards, gateways, exhaustion, edge cases.
- `tests/test_routing_engine.py`: (105 tests) Single vs Multi-Area OSPF, 50-subnet threshold, eBGP, ABR/ASBR flags.
- `tests/test_explainability.py`: (13 tests) 6-point justification format, dynamic parameter updates.
- `tests/test_config_generator.py`: (12 tests) Cisco syntax, explicit trunk allowed lists, SVI matching, QoS, IPsec.
- `tests/test_integration_profiles.py`: (6 tests) End-to-end execution of all 3 presets and error safety.
- **Total:** **416 unit and integration tests (100% passing)**.

---

## 6. Generating & Downloading Exports

The three mandatory Cisco configuration exports can be generated directly from the web UI (under the **Export Deliverables** tab) or programmatically via Python CLI:

```powershell
py -c "from generator.cisco_ios import export_preset_configs; export_preset_configs()"
```

Generated deliverable files located in `exports/`:
- `exports/campus_lan_config.txt` (Complete configuration for Building-A, Building-B, and Building-C)
- `exports/metro_man_config.txt` (Complete configuration for HQ, Site_B, and Site_C with QoS)
- `exports/global_wan_config.txt` (Complete configuration for 4 city routers and Cloud VPC with BGP & IPsec)

---

## 7. Known Limitations & Simulator Verification Status

Per Section 14 and 18 of `PROJECT_SPEC.md`, verification status is documented honestly:

1. **Simulator Verification Status:**
   - All generated Cisco IOS commands use standard Cisco IOS 15.x / IOS-XE syntax.
   - External execution inside Cisco Packet Tracer or GNS3/EVE-NG is to be verified by the evaluator using the exported text files. The codebase does not claim physical hardware testing has occurred where it has not.
2. **Structured Placeholders:**
   - Production secrets (enable secret passwords, BGP peer public IPs, IPsec pre-shared keys) use explicit placeholders (e.g. `<ENTER_SECURE_ENABLE_SECRET>`, `<REMOTE-PEER-IP-PLACEHOLDER>`). These MUST be populated prior to production deployment.
3. **Physical Media Assumption:**
   - The 400 m boundary for OM4 multimode fiber reflects the assignment's baseline recommendation. Real-world optical links must be validated against specific transceiver optical power budgets and connector insertion losses.
