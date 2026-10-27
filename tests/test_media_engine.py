"""
tests/test_media_engine.py
--------------------------
Unit tests for engine/media_engine.py.

Coverage (per PROJECT_SPEC.md Section 11 — Media tests):
---------------------------------------------------------
  ✓ 100 m, 101 m, 400 m, 401 m boundary values
  ✓ Copper request over 100 m → PhysicalDistanceViolationError
  ✓ Invalid / negative distance → ValueError
  ✓ Zero distance → virtual link (no physical medium)
  ✓ Requested-medium conflicts (copper too long, MMF too long)
  ✓ Over-specified but compliant requests (MMF/SMF where copper suffices)
  ✓ Transceiver type selection (SR vs LR vs ER)
  ✓ Wavelength correctness (850 nm SR, 1310 nm LR, 1550 nm ER)
  ✓ LR/ER threshold at 10 km
  ✓ Attenuation warning for copper violation
  ✓ Attenuation warning for long OM4 runs (>300 m)
  ✓ Assumptions list not empty for physical links
  ✓ Rule applied field matches decision
  ✓ Explanation changes with different inputs (not static)
  ✓ evaluate_all_links() processes a list of links
  ✓ raise_on_violation=False records violation without raising
  ✓ Medium aliases (Cat6a, OM4, OS2, etc.)
  ✓ Very long SMF link (>40 km) triggers DWDM assumption warning
  ✓ Bandwidth > 10 Gbps triggers assumption note
"""

import pytest

from engine.media_engine import (
    MediaDecision,
    MediumType,
    ViolationSeverity,
    PhysicalDistanceViolationError,
    COPPER_MAX_M,
    MMF_MAX_M,
    LR_MAX_KM,
    evaluate_link,
    evaluate_all_links,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _eval(distance_m, requested_medium=None, bandwidth_gbps=None, raise_on_violation=False):
    """Convenience wrapper: does not raise by default."""
    return evaluate_link(
        distance_m=distance_m,
        requested_medium=requested_medium,
        bandwidth_gbps=bandwidth_gbps,
        raise_on_violation=raise_on_violation,
    )


# ---------------------------------------------------------------------------
# Exact boundary values
# ---------------------------------------------------------------------------

class TestDistanceBoundaries:
    """Test the exact assignment boundary points."""

    def test_100m_is_copper(self):
        d = _eval(100)
        assert d.recommended_medium == MediumType.COPPER, \
            f"100 m should be copper, got {d.recommended_medium}"

    def test_101m_is_mmf(self):
        d = _eval(101)
        assert d.recommended_medium == MediumType.MMF, \
            f"101 m should be MMF, got {d.recommended_medium}"

    def test_400m_is_mmf(self):
        d = _eval(400)
        assert d.recommended_medium == MediumType.MMF, \
            f"400 m should be MMF, got {d.recommended_medium}"

    def test_401m_is_smf(self):
        d = _eval(401)
        assert d.recommended_medium == MediumType.SMF, \
            f"401 m should be SMF, got {d.recommended_medium}"

    def test_1m_is_copper(self):
        d = _eval(1)
        assert d.recommended_medium == MediumType.COPPER

    def test_50m_is_copper(self):
        d = _eval(50)
        assert d.recommended_medium == MediumType.COPPER

    def test_200m_is_mmf(self):
        d = _eval(200)
        assert d.recommended_medium == MediumType.MMF

    def test_1000m_is_smf(self):
        d = _eval(1000)
        assert d.recommended_medium == MediumType.SMF

    def test_35km_is_smf(self):
        d = _eval(35_000)
        assert d.recommended_medium == MediumType.SMF

    def test_copper_boundary_inclusive(self):
        """COPPER_MAX_M itself must select copper."""
        d = _eval(COPPER_MAX_M)
        assert d.recommended_medium == MediumType.COPPER

    def test_copper_boundary_plus_one(self):
        """COPPER_MAX_M + 1 must cross into MMF."""
        d = _eval(COPPER_MAX_M + 1)
        assert d.recommended_medium == MediumType.MMF

    def test_mmf_boundary_inclusive(self):
        """MMF_MAX_M itself must select MMF."""
        d = _eval(MMF_MAX_M)
        assert d.recommended_medium == MediumType.MMF

    def test_mmf_boundary_plus_one(self):
        """MMF_MAX_M + 1 must cross into SMF."""
        d = _eval(MMF_MAX_M + 1)
        assert d.recommended_medium == MediumType.SMF


# ---------------------------------------------------------------------------
# Ethernet standards and transceivers
# ---------------------------------------------------------------------------

class TestEthernetStandards:

    def test_copper_standard_contains_10gbase_t(self):
        d = _eval(100)
        assert "10GBASE-T" in d.ethernet_standard

    def test_mmf_standard_contains_10gbase_sr(self):
        d = _eval(200)
        assert "10GBASE-SR" in d.ethernet_standard

    def test_smf_lr_standard_for_short_smf(self):
        """Links ≤10 km on SMF should use LR."""
        d = _eval(5000)  # 5 km
        assert "LR" in d.ethernet_standard, \
            f"5 km SMF should be LR, got {d.ethernet_standard}"

    def test_smf_er_standard_for_long_smf(self):
        """Links >10 km on SMF should use ER."""
        d = _eval(15_000)  # 15 km
        assert "ER" in d.ethernet_standard, \
            f"15 km SMF should be ER, got {d.ethernet_standard}"

    def test_lr_threshold_exactly_10km(self):
        """Exactly 10 km should be LR (boundary inclusive)."""
        d = _eval(LR_MAX_KM * 1000)
        assert "LR" in d.ethernet_standard

    def test_er_threshold_just_above_10km(self):
        """10,001 m should be ER."""
        d = _eval(LR_MAX_KM * 1000 + 1)
        assert "ER" in d.ethernet_standard


# ---------------------------------------------------------------------------
# Wavelengths
# ---------------------------------------------------------------------------

class TestWavelengths:

    def test_copper_has_no_wavelength(self):
        d = _eval(50)
        assert d.wavelength_nm is None

    def test_virtual_has_no_wavelength(self):
        d = _eval(0)
        assert d.wavelength_nm is None

    def test_mmf_sr_wavelength_is_850nm(self):
        d = _eval(200)
        assert d.wavelength_nm == 850, f"SR should be 850 nm, got {d.wavelength_nm}"

    def test_smf_lr_wavelength_is_1310nm(self):
        d = _eval(5000)
        assert d.wavelength_nm == 1310, f"LR should be 1310 nm, got {d.wavelength_nm}"

    def test_smf_er_wavelength_is_1550nm(self):
        d = _eval(15_000)
        assert d.wavelength_nm == 1550, f"ER should be 1550 nm, got {d.wavelength_nm}"


# ---------------------------------------------------------------------------
# Zero distance — virtual / cloud link
# ---------------------------------------------------------------------------

class TestVirtualLink:

    def test_zero_distance_is_virtual(self):
        d = _eval(0)
        assert d.recommended_medium == MediumType.VIRTUAL
        assert d.is_virtual is True

    def test_virtual_has_no_violation(self):
        d = _eval(0)
        assert not d.violation
        assert d.violation_severity == ViolationSeverity.NONE

    def test_virtual_explanation_mentions_virtual_or_cloud(self):
        d = _eval(0)
        assert "virtual" in d.explanation.lower() or "cloud" in d.explanation.lower()

    def test_virtual_assumptions_not_empty(self):
        d = _eval(0)
        assert len(d.assumptions) > 0


# ---------------------------------------------------------------------------
# Copper violation — the mandatory PhysicalDistanceViolationError
# ---------------------------------------------------------------------------

class TestCopperViolation:

    def test_copper_request_over_100m_raises_by_default(self):
        """With raise_on_violation=True (default), copper >100 m must raise."""
        with pytest.raises(PhysicalDistanceViolationError) as exc_info:
            evaluate_link(distance_m=150, requested_medium="copper", raise_on_violation=True)

        exc = exc_info.value
        assert exc.distance_m == 150
        assert exc.limit_m == COPPER_MAX_M
        assert "copper" in exc.requested_medium.lower()
        assert "100" in exc.message

    def test_copper_request_at_101m_raises(self):
        with pytest.raises(PhysicalDistanceViolationError):
            evaluate_link(distance_m=101, requested_medium="copper", raise_on_violation=True)

    def test_copper_request_at_400m_raises(self):
        with pytest.raises(PhysicalDistanceViolationError):
            evaluate_link(distance_m=400, requested_medium="copper", raise_on_violation=True)

    def test_copper_request_over_100m_no_raise_records_violation(self):
        d = _eval(200, requested_medium="copper")
        assert d.violation is True
        assert d.violation_severity == ViolationSeverity.ERROR
        assert "100" in d.violation_message or "copper" in d.violation_message.lower()

    def test_copper_violation_has_attenuation_warning(self):
        d = _eval(200, requested_medium="copper")
        assert "COPPER DISTANCE VIOLATION" in d.attenuation_warning or \
               "copper" in d.attenuation_warning.lower()

    def test_copper_at_100m_does_not_raise(self):
        """Copper at exactly 100 m is compliant — must not raise."""
        d = evaluate_link(distance_m=100, requested_medium="copper", raise_on_violation=True)
        assert not d.violation

    def test_copper_below_100m_no_violation(self):
        d = _eval(50, requested_medium="copper")
        assert not d.violation
        assert d.recommended_medium == MediumType.COPPER

    def test_violation_exception_has_correct_attributes(self):
        try:
            evaluate_link(distance_m=500, requested_medium="copper", raise_on_violation=True)
            pytest.fail("Expected PhysicalDistanceViolationError")
        except PhysicalDistanceViolationError as e:
            assert e.distance_m == 500
            assert e.limit_m == 100
            assert "copper" in e.requested_medium


# ---------------------------------------------------------------------------
# MMF violation (>400 m)
# ---------------------------------------------------------------------------

class TestMmfViolation:

    def test_mmf_request_over_400m_is_error(self):
        d = _eval(500, requested_medium="mmf")
        assert d.violation is True
        assert d.violation_severity == ViolationSeverity.ERROR

    def test_mmf_request_over_400m_records_message(self):
        d = _eval(500, requested_medium="mmf")
        assert "400" in d.violation_message or "multimode" in d.violation_message.lower()

    def test_mmf_at_400m_is_compliant(self):
        d = _eval(400, requested_medium="mmf")
        assert not d.violation or d.violation_severity != ViolationSeverity.ERROR

    def test_mmf_request_over_400m_no_raise_records_violation(self):
        d = evaluate_link(distance_m=1000, requested_medium="mmf", raise_on_violation=False)
        assert d.violation is True


# ---------------------------------------------------------------------------
# Over-specified but technically compliant requests (warnings, not errors)
# ---------------------------------------------------------------------------

class TestOverSpecified:

    def test_mmf_for_copper_range_link_is_warning_not_error(self):
        d = _eval(50, requested_medium="mmf")
        assert not d.violation or d.violation_severity == ViolationSeverity.WARNING
        # Engine must accept MMF at ≤100 m (over-specified is valid)

    def test_smf_for_copper_range_link_is_warning_not_error(self):
        d = _eval(50, requested_medium="smf")
        assert not d.violation or d.violation_severity == ViolationSeverity.WARNING

    def test_smf_for_mmf_range_link_is_warning_not_error(self):
        d = _eval(200, requested_medium="smf")
        assert not d.violation or d.violation_severity == ViolationSeverity.WARNING

    def test_over_specified_mmf_uses_mmf_as_recommended(self):
        """When SMF/MMF is over-specified, the engine honors the request."""
        d = _eval(50, requested_medium="mmf")
        assert d.recommended_medium == MediumType.MMF

    def test_over_specified_smf_uses_smf_as_recommended(self):
        d = _eval(50, requested_medium="smf")
        assert d.recommended_medium == MediumType.SMF


# ---------------------------------------------------------------------------
# Invalid inputs
# ---------------------------------------------------------------------------

class TestInvalidInputs:

    def test_negative_distance_raises_value_error(self):
        with pytest.raises(ValueError, match="non-negative"):
            evaluate_link(distance_m=-1)

    def test_string_distance_raises_value_error(self):
        with pytest.raises((ValueError, TypeError)):
            evaluate_link(distance_m="far")

    def test_nan_distance_raises_value_error(self):
        import math
        with pytest.raises(ValueError):
            evaluate_link(distance_m=float("nan"))

    def test_inf_distance_raises_value_error(self):
        with pytest.raises(ValueError):
            evaluate_link(distance_m=float("inf"))


# ---------------------------------------------------------------------------
# Medium aliases
# ---------------------------------------------------------------------------

class TestMediumAliases:

    def test_alias_cat6a_is_treated_as_copper(self):
        """'Cat6a' should normalise to copper."""
        d = _eval(50, requested_medium="Cat6a")
        assert d.recommended_medium == MediumType.COPPER
        assert not d.violation

    def test_alias_om4_is_treated_as_mmf(self):
        d = _eval(200, requested_medium="OM4")
        assert d.recommended_medium == MediumType.MMF
        assert not d.violation

    def test_alias_os2_is_treated_as_smf(self):
        d = _eval(500, requested_medium="OS2")
        assert d.recommended_medium == MediumType.SMF
        assert not d.violation

    def test_alias_utp_is_treated_as_copper(self):
        d = _eval(80, requested_medium="UTP")
        assert d.recommended_medium == MediumType.COPPER

    def test_alias_cat6a_violation_over_100m(self):
        """Cat6a alias must still trigger a violation over 100 m."""
        with pytest.raises(PhysicalDistanceViolationError):
            evaluate_link(distance_m=200, requested_medium="Cat6a", raise_on_violation=True)


# ---------------------------------------------------------------------------
# Explanation content checks
# ---------------------------------------------------------------------------

class TestExplanationContent:

    def test_copper_explanation_mentions_distance(self):
        d = _eval(80)
        assert "80" in d.explanation

    def test_mmf_explanation_mentions_distance(self):
        d = _eval(250)
        assert "250" in d.explanation

    def test_smf_explanation_mentions_distance(self):
        d = _eval(600)
        assert "600" in d.explanation

    def test_explanation_changes_with_distance(self):
        """Explanations must not be static — they must reflect the actual distance."""
        d1 = _eval(80)
        d2 = _eval(250)
        d3 = _eval(600)
        # All three should differ (different distances, different media)
        assert d1.explanation != d2.explanation
        assert d2.explanation != d3.explanation

    def test_mmf_explanation_has_technical_qualification(self):
        """OM4 explanation must carry the spec's technical qualification."""
        d = _eval(350)
        assert "400" in d.explanation  # mentions the 400 m boundary
        assert "assignment" in d.explanation.lower() or "verify" in d.explanation.lower()

    def test_smf_explanation_mentions_wavelength_context(self):
        d = _eval(500)
        assert "1310" in d.explanation or "LR" in d.explanation

    def test_violation_explanation_mentions_non_compliant(self):
        d = _eval(200, requested_medium="copper")
        assert "non-compliant" in d.explanation.lower() or "violation" in d.violation_message.lower()


# ---------------------------------------------------------------------------
# Assumptions
# ---------------------------------------------------------------------------

class TestAssumptions:

    def test_copper_assumptions_not_empty(self):
        d = _eval(50)
        assert len(d.assumptions) > 0

    def test_mmf_assumptions_mention_optical_budget(self):
        d = _eval(200)
        assert any("optical" in a.lower() or "budget" in a.lower() for a in d.assumptions)

    def test_smf_assumptions_mention_os2(self):
        d = _eval(600)
        assert any("os2" in a.lower() or "single-mode" in a.lower() for a in d.assumptions)

    def test_high_bandwidth_assumption_present(self):
        d = _eval(200, bandwidth_gbps=40)
        assert any("40" in a or "25" in a or "bandwidth" in a.lower() for a in d.assumptions)

    def test_long_smf_assumptions_mention_er(self):
        d = _eval(20_000)  # 20 km
        assert any("ER" in a or "er" in a.lower() or "1550" in a for a in d.assumptions)


# ---------------------------------------------------------------------------
# Attenuation warnings
# ---------------------------------------------------------------------------

class TestAttenuationWarnings:

    def test_copper_violation_triggers_attenuation_warning(self):
        d = _eval(200, requested_medium="copper")
        assert d.attenuation_warning != "", \
            "Copper violation must produce an attenuation warning."

    def test_long_mmf_run_triggers_attenuation_warning(self):
        """OM4 runs > 300 m should warn about approaching the optical limit."""
        d = _eval(380)
        assert d.attenuation_warning != "", \
            "Long OM4 run (380 m) should produce an attenuation warning."

    def test_short_mmf_no_attenuation_warning(self):
        """OM4 at 150 m is comfortably within reach — no attenuation warning needed."""
        d = _eval(150)
        assert d.attenuation_warning == "", \
            f"Short OM4 run should not trigger a warning; got: {d.attenuation_warning}"

    def test_very_long_smf_triggers_budget_warning(self):
        """SMF links > 40 km require DWDM/amplification — must warn."""
        d = _eval(50_000)  # 50 km
        assert d.attenuation_warning != "", \
            "50 km SMF link should trigger a budget/DWDM warning."

    def test_normal_smf_10km_no_extra_warning(self):
        """A 10 km SMF link is within LR spec — no DWDM warning needed."""
        d = _eval(10_000)
        assert "DWDM" not in d.attenuation_warning and "amplification" not in d.attenuation_warning


# ---------------------------------------------------------------------------
# Rule applied field
# ---------------------------------------------------------------------------

class TestRuleApplied:

    def test_copper_rule_applied_mentions_100m(self):
        d = _eval(80)
        assert "100" in d.rule_applied

    def test_mmf_rule_applied_mentions_400m(self):
        d = _eval(200)
        assert "400" in d.rule_applied

    def test_smf_rule_applied_mentions_400m(self):
        d = _eval(500)
        assert "400" in d.rule_applied

    def test_virtual_rule_applied_mentions_virtual(self):
        d = _eval(0)
        assert "virtual" in d.rule_applied.lower()


# ---------------------------------------------------------------------------
# evaluate_all_links()
# ---------------------------------------------------------------------------

class TestEvaluateAllLinks:

    def _make_links(self):
        return [
            {"from": "A", "to": "B", "distance_m": 80,     "bandwidth_gbps": 10},
            {"from": "A", "to": "C", "distance_m": 250,    "bandwidth_gbps": 10},
            {"from": "B", "to": "C", "distance_m": 15_000, "bandwidth_gbps": 1},
        ]

    def test_returns_one_result_per_link(self):
        links = self._make_links()
        results = evaluate_all_links(links)
        assert len(results) == len(links)

    def test_each_result_has_media_decision(self):
        results = evaluate_all_links(self._make_links())
        for r in results:
            assert "media_decision" in r
            assert isinstance(r["media_decision"], MediaDecision)

    def test_original_link_fields_preserved(self):
        links = self._make_links()
        results = evaluate_all_links(links)
        assert results[0]["from"] == "A"
        assert results[0]["to"] == "B"
        assert results[0]["distance_m"] == 80

    def test_correct_media_per_link(self):
        results = evaluate_all_links(self._make_links())
        assert results[0]["media_decision"].recommended_medium == MediumType.COPPER
        assert results[1]["media_decision"].recommended_medium == MediumType.MMF
        assert results[2]["media_decision"].recommended_medium == MediumType.SMF

    def test_violation_does_not_raise_by_default(self):
        """evaluate_all_links with raise_on_violation=False must not raise."""
        links = [{"from": "A", "to": "B", "distance_m": 300, "requested_medium": "copper"}]
        results = evaluate_all_links(links, raise_on_violation=False)
        assert results[0]["media_decision"].violation is True

    def test_violation_raises_when_requested(self):
        links = [{"from": "A", "to": "B", "distance_m": 300, "requested_medium": "copper"}]
        with pytest.raises(PhysicalDistanceViolationError):
            evaluate_all_links(links, raise_on_violation=True)

    def test_empty_link_list(self):
        results = evaluate_all_links([])
        assert results == []


# ---------------------------------------------------------------------------
# Profile integration — preset links pass media evaluation
# ---------------------------------------------------------------------------

class TestProfileIntegration:

    def test_campus_lan_links_all_produce_decisions(self):
        from profiles.presets import get_preset, CAMPUS_LAN
        plan = get_preset(CAMPUS_LAN)
        results = evaluate_all_links(plan["links"])
        assert len(results) == len(plan["links"])
        for r in results:
            assert isinstance(r["media_decision"], MediaDecision)

    def test_campus_lan_links_are_mmf(self):
        """Campus links are 180–320 m — all should be OM4 MMF."""
        from profiles.presets import get_preset, CAMPUS_LAN
        plan = get_preset(CAMPUS_LAN)
        results = evaluate_all_links(plan["links"])
        for r in results:
            d = r["media_decision"]
            assert d.recommended_medium == MediumType.MMF, \
                f"Campus link {r['from']}→{r['to']} ({r['distance_m']} m) " \
                f"expected MMF, got {d.recommended_medium}"

    def test_metro_man_links_are_smf(self):
        """Metro MAN links are 15–35 km — all should be OS2 SMF."""
        from profiles.presets import get_preset, METRO_MAN
        plan = get_preset(METRO_MAN)
        results = evaluate_all_links(plan["links"])
        for r in results:
            d = r["media_decision"]
            assert d.recommended_medium == MediumType.SMF, \
                f"Metro link {r['from']}→{r['to']} ({r['distance_m']} m) " \
                f"expected SMF, got {d.recommended_medium}"

    def test_global_wan_has_virtual_link(self):
        """Global WAN has a 0 m cloud link — must be VIRTUAL."""
        from profiles.presets import get_preset, GLOBAL_WAN
        plan = get_preset(GLOBAL_WAN)
        results = evaluate_all_links(plan["links"])
        virtual_links = [r for r in results if r["media_decision"].is_virtual]
        assert len(virtual_links) >= 1, "Global WAN must have at least one virtual link."

    def test_global_wan_physical_links_are_smf(self):
        """Global WAN physical links are hundreds of km — must be SMF."""
        from profiles.presets import get_preset, GLOBAL_WAN
        plan = get_preset(GLOBAL_WAN)
        results = evaluate_all_links(plan["links"])
        for r in results:
            d = r["media_decision"]
            if not d.is_virtual:
                assert d.recommended_medium == MediumType.SMF, \
                    f"WAN link {r['from']}→{r['to']} ({r['distance_m']} m) " \
                    f"expected SMF, got {d.recommended_medium}"
