"""
engine/media_engine.py
----------------------
Deterministic physical media decision engine for NetArchitect.

Implements the assignment's three distance-based decision boundaries and the
mandatory copper-limit violation behavior.  Every decision is returned as a
structured MediaDecision object so that the explainability engine and the UI
can consume real results rather than static text.

Assignment decision boundaries (Section 6 of PROJECT_SPEC.md)
--------------------------------------------------------------
  Distance        Medium              Ethernet standard
  ≤ 100 m         Cat6a copper        10GBASE-T
  101 – 400 m     OM4 multimode fiber 10GBASE-SR (short-reach optics)
  > 400 m         OS2 single-mode     10GBASE-LR / 10GBASE-ER (long-reach)

Special cases
-------------
  distance = 0 m  Virtual / cloud link — no physical media rules apply.

Violation behavior
------------------
  If the caller explicitly requests copper for a link > 100 m, the engine
  raises PhysicalDistanceViolationError.  It also returns the violation as a
  structured field so the UI can surface it without catching the exception
  if prefer_structured=True is set.

Technical qualification
-----------------------
  The 400 m boundary is the simplified assignment rule, not a universal
  guarantee for every OM4/transceiver combination.  Explanations make this
  clear.  The 100 m copper limit refers to the complete Ethernet channel
  (horizontal + patch cables), per IEEE 802.3 10GBASE-T.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Public exception
# ---------------------------------------------------------------------------

class PhysicalDistanceViolationError(ValueError):
    """
    Raised when the caller explicitly requests a medium that violates the
    IEEE distance limit for that medium type.

    Attributes
    ----------
    distance_m : float
        The link distance that caused the violation.
    requested_medium : str
        The medium that was requested ('copper', 'mmf', 'smf').
    limit_m : float
        The maximum distance for the requested medium per assignment rules.
    message : str
        Human-readable violation description.
    """

    def __init__(
        self,
        distance_m: float,
        requested_medium: str,
        limit_m: float,
        message: str,
    ) -> None:
        super().__init__(message)
        self.distance_m = distance_m
        self.requested_medium = requested_medium
        self.limit_m = limit_m
        self.message = message


# ---------------------------------------------------------------------------
# Enumerations and constants
# ---------------------------------------------------------------------------

class MediumType(str, Enum):
    COPPER  = "copper"   # Cat6a twisted pair
    MMF     = "mmf"      # Multimode fiber (OM4)
    SMF     = "smf"      # Single-mode fiber (OS2)
    VIRTUAL = "virtual"  # No physical medium (cloud / zero-distance link)

class ViolationSeverity(str, Enum):
    NONE    = "none"
    WARNING = "warning"   # Non-blocking issue
    ERROR   = "error"     # Blocking — requested medium is non-compliant


# Distance thresholds (metres) — assignment rules, Section 6.
COPPER_MAX_M:  float = 100.0   # IEEE 802.3 Cat6a 10GBASE-T channel limit
MMF_MAX_M:     float = 400.0   # OM4 boundary per assignment decision table

# Ethernet standard labels
STANDARD_COPPER  = "10GBASE-T (IEEE 802.3an)"
STANDARD_MMF_SR  = "10GBASE-SR (IEEE 802.3ae)"
STANDARD_SMF_LR  = "10GBASE-LR (IEEE 802.3ae)"
STANDARD_SMF_ER  = "10GBASE-ER (IEEE 802.3ae)"  # For very long runs > ~10 km

# Transceiver / optic labels
TRANSCEIVER_COPPER = "RJ-45 / built-in PHY"
TRANSCEIVER_SR     = "SFP+ SR (850 nm, multimode)"
TRANSCEIVER_LR     = "SFP+ LR (1310 nm, single-mode)"
TRANSCEIVER_ER     = "SFP+ ER (1550 nm, single-mode)"

# Wavelengths (nm)
WAVELENGTH_SR  = 850
WAVELENGTH_LR  = 1310
WAVELENGTH_ER  = 1550

# Threshold above which ER optics are more appropriate than LR
# IEEE 802.3ae 10GBASE-LR reach: up to ~10 km on OS2.
LR_MAX_KM: float = 10.0


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class MediaDecision:
    """
    Structured result from evaluate_link().

    All fields reflect the actual inputs and the rule applied — nothing is
    fabricated.  The UI and explainability engine must use these fields.

    Attributes
    ----------
    distance_m : float
        Input link distance.
    bandwidth_gbps : float | None
        Input bandwidth request (informational).
    requested_medium : str | None
        The medium explicitly requested by the caller, if any.
    recommended_medium : MediumType
        The medium selected by the engine per assignment rules.
    ethernet_standard : str
        The applicable IEEE Ethernet standard label.
    transceiver : str
        The recommended transceiver / PHY type.
    wavelength_nm : int | None
        Optical wavelength in nm for fiber links; None for copper / virtual.
    cable_type : str
        Cable type description.
    violation : bool
        True if the requested medium is non-compliant.
    violation_severity : ViolationSeverity
        NONE, WARNING, or ERROR.
    violation_message : str
        Human-readable description of the violation, or empty string.
    attenuation_warning : str
        Signal integrity / attenuation notes, or empty string.
    explanation : str
        Engineering justification generated from actual inputs and rule applied.
    assumptions : list[str]
        Explicit assumptions made by the engine.
    rule_applied : str
        The decision rule that was evaluated (for auditability).
    is_virtual : bool
        True for zero-distance (cloud / virtual) links.
    """
    distance_m:          float
    bandwidth_gbps:      Optional[float]
    requested_medium:    Optional[str]
    recommended_medium:  MediumType
    ethernet_standard:   str
    transceiver:         str
    wavelength_nm:       Optional[int]
    cable_type:          str
    violation:           bool
    violation_severity:  ViolationSeverity
    violation_message:   str
    attenuation_warning: str
    explanation:         str
    assumptions:         list[str]
    rule_applied:        str
    is_virtual:          bool


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_medium(medium: Optional[str]) -> Optional[str]:
    """Normalise medium string to lowercase stripped form, or None."""
    if medium is None:
        return None
    m = medium.strip().lower()
    # Accept common aliases
    aliases = {
        "cat6a": "copper",
        "cat6": "copper",
        "utp": "copper",
        "copper": "copper",
        "twisted pair": "copper",
        "multimode": "mmf",
        "om4": "mmf",
        "om3": "mmf",
        "mmf": "mmf",
        "multimode fiber": "mmf",
        "single-mode": "smf",
        "singlemode": "smf",
        "os2": "smf",
        "smf": "smf",
        "single mode fiber": "smf",
        "single-mode fiber": "smf",
        "fiber": "smf",   # ambiguous — treated as SMF (longer reach) with a note
    }
    return aliases.get(m, m)


def _select_smf_standard(distance_m: float) -> tuple[str, str, int]:
    """
    Choose between LR and ER optics for SMF based on distance.

    Returns (ethernet_standard, transceiver, wavelength_nm).

    Note: 10GBASE-LR is rated for up to ~10 km on OS2.  Beyond that,
    10GBASE-ER (up to ~40 km) is more appropriate.  Very long spans (>40 km)
    would require amplification or DWDM — this is flagged as an assumption.
    """
    distance_km = distance_m / 1000.0
    if distance_km <= LR_MAX_KM:
        return STANDARD_SMF_LR, TRANSCEIVER_LR, WAVELENGTH_LR
    else:
        return STANDARD_SMF_ER, TRANSCEIVER_ER, WAVELENGTH_ER


def _build_explanation(
    distance_m: float,
    recommended: MediumType,
    ethernet_standard: str,
    rule_applied: str,
    requested_medium: Optional[str],
    violation: bool,
    is_virtual: bool,
) -> str:
    """Generate a factual engineering explanation from the actual decision inputs."""
    if is_virtual:
        return (
            f"Link distance is 0 m (virtual or cloud connection). "
            "No physical medium selection is applicable. "
            "Connectivity is assumed to be provided by the cloud provider or "
            "virtual network infrastructure."
        )

    dist_str = (
        f"{distance_m:.0f} m"
        if distance_m < 1000
        else f"{distance_m / 1000:.1f} km ({distance_m:.0f} m)"
    )

    if recommended == MediumType.COPPER:
        body = (
            f"Cat6a copper was recommended because the link distance is {dist_str}, "
            f"within the 100 m IEEE 802.3 channel limit for 10GBASE-T. "
            f"Cat6a (Class Ea) supports 10 Gbit/s to 100 m. "
            f"The applicable standard is {ethernet_standard}. "
            "No fiber optics are required at this distance."
        )
    elif recommended == MediumType.MMF:
        body = (
            f"OM4 multimode fiber was recommended because the link distance is {dist_str}, "
            f"which exceeds the 100 m copper channel limit but is within the "
            f"assignment's 400 m OM4 recommendation boundary. "
            f"OM4 fiber with short-reach (SR) optics at 850 nm supports 10 Gbit/s "
            f"up to approximately 400 m. "
            f"The applicable standard is {ethernet_standard}. "
            "Note: the 400 m boundary is the simplified assignment decision rule. "
            "Actual OM4 reach depends on the specific transceiver, fiber quality, "
            "connector loss, and optical budget — verify against manufacturer data "
            "before deployment."
        )
    else:  # SMF
        dist_km = distance_m / 1000.0
        body = (
            f"OS2 single-mode fiber was recommended because the link distance is {dist_str}, "
            f"beyond the 400 m OM4 recommendation boundary. "
            f"OS2 SMF with long-reach optics supports distances well beyond 400 m. "
            f"The applicable standard is {ethernet_standard}. "
        )
        if dist_km <= LR_MAX_KM:
            body += (
                f"At {dist_km:.1f} km, 10GBASE-LR (1310 nm) optics are appropriate "
                f"(rated to approximately 10 km on OS2). "
            )
        else:
            body += (
                f"At {dist_km:.1f} km, 10GBASE-ER (1550 nm) optics are required "
                f"(10GBASE-LR is rated to approximately 10 km; ER extends to ~40 km). "
            )

    if violation and requested_medium:
        body += (
            f" The caller requested '{requested_medium}', which is non-compliant "
            f"at {dist_str}. The compliant alternative above is recommended instead."
        )

    return body


def _build_attenuation_warning(
    distance_m: float,
    recommended: MediumType,
    violation: bool,
    requested_medium: Optional[str],
) -> str:
    """Return an attenuation / signal integrity warning string when relevant."""
    parts: list[str] = []

    if violation and requested_medium and _normalise_medium(requested_medium) == "copper":
        excess_m = distance_m - COPPER_MAX_M
        # Cat6a attenuation at 500 MHz is ~24.5 dB/100 m; at longer runs this
        # exceeds the channel insertion loss budget (max 20.9 dB for Class Ea).
        parts.append(
            f"COPPER DISTANCE VIOLATION: The requested copper link is {distance_m:.0f} m — "
            f"{excess_m:.0f} m beyond the 100 m IEEE 802.3 10GBASE-T channel limit. "
            f"At this length, Cat6a attenuation will exceed the maximum channel insertion "
            f"loss budget (20.9 dB for Class Ea at 500 MHz), causing link failure or "
            f"severe degradation. Do not deploy copper at this distance."
        )

    if recommended == MediumType.MMF and distance_m > 300:
        parts.append(
            f"At {distance_m:.0f} m, this link is approaching the practical OM4 reach "
            "limit for 10GBASE-SR. Verify the optical power budget against actual "
            "connector, splice, and bend losses before deployment."
        )

    distance_km = distance_m / 1000.0
    if recommended == MediumType.SMF and distance_km > 40:
        parts.append(
            f"At {distance_km:.1f} km, this link exceeds the typical 10GBASE-ER reach "
            "(~40 km on OS2). DWDM, optical amplification, or a carrier WAN service "
            "will be required. The planner cannot verify optical feasibility at this "
            "distance without a detailed link budget."
        )

    return "  ".join(parts)


def _build_assumptions(
    distance_m: float,
    recommended: MediumType,
    bandwidth_gbps: Optional[float],
    is_virtual: bool,
) -> list[str]:
    """Return a list of explicit assumptions made by the engine."""
    if is_virtual:
        return [
            "Virtual link: physical media rules are not applied.",
            "Connectivity is assumed to be provided externally (cloud / virtual switch).",
        ]

    assumptions: list[str] = [
        "All distances refer to the complete cable channel (horizontal + patch cables).",
    ]

    if recommended == MediumType.COPPER:
        assumptions.append(
            "10GBASE-T is assumed; the network device must support 10GBASE-T on its copper port."
        )
        assumptions.append(
            "Environmental EMI and cable quality are assumed acceptable for Cat6a at this distance."
        )

    if recommended == MediumType.MMF:
        assumptions.append(
            "OM4 fiber (50/125 µm) is assumed. OM3 fiber reduces effective reach."
        )
        assumptions.append(
            "Both endpoints are assumed to have SFP+ SR transceiver slots."
        )
        assumptions.append(
            "Optical budget has not been calculated — verify against actual fiber run, "
            "connector count, and transceiver specifications."
        )

    if recommended == MediumType.SMF:
        distance_km = distance_m / 1000.0
        assumptions.append(
            "OS2 single-mode fiber (9/125 µm) is assumed."
        )
        assumptions.append(
            "Both endpoints are assumed to have SFP+ LR or ER transceiver slots."
        )
        if distance_km > 10:
            assumptions.append(
                f"At {distance_km:.1f} km, SFP+ ER (1550 nm, ~40 km reach) is assumed. "
                "Verify optical budget and chromatic dispersion against the actual fiber span."
            )
        assumptions.append(
            "Optical power budget has not been calculated — a full link budget is "
            "required before procurement."
        )

    if bandwidth_gbps is not None and bandwidth_gbps > 10:
        assumptions.append(
            f"Requested bandwidth ({bandwidth_gbps} Gbps) exceeds the 10 Gbps standard "
            "assumed here. A higher-rate standard (25GBASE, 40GBASE, 100GBASE) may be needed."
        )

    return assumptions


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate_link(
    distance_m: float,
    requested_medium: Optional[str] = None,
    bandwidth_gbps: Optional[float] = None,
    raise_on_violation: bool = True,
) -> MediaDecision:
    """
    Evaluate the physical medium for a single network link.

    Parameters
    ----------
    distance_m : float
        Link length in metres.  Must be >= 0.
    requested_medium : str | None
        Medium explicitly requested by the user: 'copper', 'mmf', 'smf',
        or None to let the engine decide.  Aliases such as 'Cat6a', 'OM4',
        'OS2' are accepted (case-insensitive).
    bandwidth_gbps : float | None
        Requested link bandwidth in Gbps (informational, influences
        assumptions only).
    raise_on_violation : bool
        If True (default), raise PhysicalDistanceViolationError when the
        requested medium is non-compliant.  If False, the violation is
        recorded in the MediaDecision and no exception is raised.

    Returns
    -------
    MediaDecision
        Fully populated structured result.

    Raises
    ------
    ValueError
        If distance_m is negative or not a number.
    PhysicalDistanceViolationError
        If raise_on_violation=True and the requested medium violates its
        distance limit.
    """
    # --- Input validation ---
    if not isinstance(distance_m, (int, float)):
        raise ValueError(
            f"distance_m must be a number, got {type(distance_m).__name__!r}."
        )
    if math.isnan(distance_m) or math.isinf(distance_m):
        raise ValueError(
            f"distance_m must be a finite number, got {distance_m!r}."
        )
    if distance_m < 0:
        raise ValueError(
            f"distance_m must be non-negative, got {distance_m}. "
            "A distance of 0 m is allowed for virtual/cloud links."
        )

    req_norm = _normalise_medium(requested_medium)

    # --- Virtual / cloud link ---
    if distance_m == 0:
        decision = MediaDecision(
            distance_m=distance_m,
            bandwidth_gbps=bandwidth_gbps,
            requested_medium=requested_medium,
            recommended_medium=MediumType.VIRTUAL,
            ethernet_standard="N/A — virtual link",
            transceiver="N/A",
            wavelength_nm=None,
            cable_type="Virtual / cloud connection",
            violation=False,
            violation_severity=ViolationSeverity.NONE,
            violation_message="",
            attenuation_warning="",
            explanation=_build_explanation(
                distance_m=distance_m,
                recommended=MediumType.VIRTUAL,
                ethernet_standard="N/A",
                rule_applied="distance=0 → virtual link",
                requested_medium=req_norm,
                violation=False,
                is_virtual=True,
            ),
            assumptions=_build_assumptions(
                distance_m=distance_m,
                recommended=MediumType.VIRTUAL,
                bandwidth_gbps=bandwidth_gbps,
                is_virtual=True,
            ),
            rule_applied="distance=0 → virtual link; no physical media decision",
            is_virtual=True,
        )
        return decision

    # --- Determine compliant medium per assignment rules ---
    if distance_m <= COPPER_MAX_M:
        compliant_medium  = MediumType.COPPER
        ethernet_standard = STANDARD_COPPER
        transceiver       = TRANSCEIVER_COPPER
        wavelength_nm     = None
        cable_type        = "Cat6a (Class Ea) UTP/STP"
        rule_applied      = f"distance ({distance_m:.0f} m) ≤ {COPPER_MAX_M:.0f} m → Cat6a copper (10GBASE-T)"
    elif distance_m <= MMF_MAX_M:
        compliant_medium  = MediumType.MMF
        ethernet_standard = STANDARD_MMF_SR
        transceiver       = TRANSCEIVER_SR
        wavelength_nm     = WAVELENGTH_SR
        cable_type        = "OM4 50/125 µm multimode fiber"
        rule_applied      = (
            f"distance ({distance_m:.0f} m) in range "
            f"({COPPER_MAX_M:.0f} m, {MMF_MAX_M:.0f} m] → OM4 MMF (10GBASE-SR)"
        )
    else:
        ethernet_standard, transceiver, wavelength_nm = _select_smf_standard(distance_m)
        compliant_medium  = MediumType.SMF
        cable_type        = "OS2 9/125 µm single-mode fiber"
        rule_applied      = (
            f"distance ({distance_m:.0f} m) > {MMF_MAX_M:.0f} m → OS2 SMF "
            f"({'10GBASE-LR' if distance_m / 1000 <= LR_MAX_KM else '10GBASE-ER'})"
        )

    # --- Violation detection ---
    violation          = False
    violation_severity = ViolationSeverity.NONE
    violation_message  = ""

    if req_norm is not None and req_norm != compliant_medium.value:
        violation          = True
        violation_severity = ViolationSeverity.ERROR

        if req_norm == "copper":
            violation_message = (
                f"Copper (Cat6a) was requested for a {distance_m:.0f} m link, "
                f"which exceeds the 100 m IEEE 802.3 10GBASE-T channel limit by "
                f"{distance_m - COPPER_MAX_M:.0f} m. "
                "Copper cannot physically support this distance at 10 Gbit/s. "
                f"Compliant alternative: {compliant_medium.value.upper()} "
                f"({ethernet_standard})."
            )
        elif req_norm == "mmf" and compliant_medium == MediumType.SMF:
            violation_message = (
                f"OM4 multimode fiber was requested for a {distance_m:.0f} m link, "
                f"which exceeds the assignment's 400 m OM4 recommendation boundary. "
                f"OM4 with 10GBASE-SR optics is not reliably specified beyond 400 m "
                "for the purposes of this assignment. "
                f"Compliant alternative: OS2 SMF ({ethernet_standard})."
            )
        elif req_norm == "mmf" and compliant_medium == MediumType.COPPER:
            # MMF for a copper-range link — not a violation, just unnecessary.
            violation          = False
            violation_severity = ViolationSeverity.WARNING
            violation_message  = (
                f"OM4 multimode fiber was requested for a {distance_m:.0f} m link. "
                "Cat6a copper would be sufficient and less expensive at this distance. "
                "MMF is accepted but is over-specified."
            )
        elif req_norm == "smf" and compliant_medium in (MediumType.COPPER, MediumType.MMF):
            # SMF for a shorter link — valid but over-specified.
            violation          = False
            violation_severity = ViolationSeverity.WARNING
            violation_message  = (
                f"OS2 single-mode fiber was requested for a {distance_m:.0f} m link. "
                f"{'Cat6a copper' if compliant_medium == MediumType.COPPER else 'OM4 MMF'} "
                "would be sufficient and less expensive at this distance. "
                "SMF is technically compliant but over-specified."
            )
        elif req_norm not in ("copper", "mmf", "smf", "virtual"):
            violation_message = (
                f"Unknown medium '{requested_medium}' requested. "
                "Recognised values: copper, mmf (OM4), smf (OS2). "
                f"Compliant recommendation: {compliant_medium.value.upper()}."
            )

    # Raise if requested and this is a hard violation
    if violation and violation_severity == ViolationSeverity.ERROR and raise_on_violation:
        raise PhysicalDistanceViolationError(
            distance_m=distance_m,
            requested_medium=req_norm or "",
            limit_m=COPPER_MAX_M if req_norm == "copper" else MMF_MAX_M,
            message=violation_message,
        )

    # For over-specified requests (WARNING), use the requested medium.
    if violation_severity == ViolationSeverity.WARNING and req_norm in ("mmf", "smf"):
        # Honor over-specified request — it is technically compliant.
        if req_norm == "mmf":
            recommended_medium = MediumType.MMF
            ethernet_standard  = STANDARD_MMF_SR
            transceiver        = TRANSCEIVER_SR
            wavelength_nm      = WAVELENGTH_SR
            cable_type         = "OM4 50/125 µm multimode fiber (over-specified)"
        else:
            std, tc, wl        = _select_smf_standard(distance_m)
            recommended_medium = MediumType.SMF
            ethernet_standard  = std
            transceiver        = tc
            wavelength_nm      = wl
            cable_type         = "OS2 9/125 µm single-mode fiber (over-specified)"
    else:
        recommended_medium = compliant_medium

    attenuation_warning = _build_attenuation_warning(
        distance_m=distance_m,
        recommended=recommended_medium,
        violation=violation and violation_severity == ViolationSeverity.ERROR,
        requested_medium=req_norm,
    )

    explanation = _build_explanation(
        distance_m=distance_m,
        recommended=recommended_medium,
        ethernet_standard=ethernet_standard,
        rule_applied=rule_applied,
        requested_medium=req_norm,
        violation=violation and violation_severity == ViolationSeverity.ERROR,
        is_virtual=False,
    )

    assumptions = _build_assumptions(
        distance_m=distance_m,
        recommended=recommended_medium,
        bandwidth_gbps=bandwidth_gbps,
        is_virtual=False,
    )

    return MediaDecision(
        distance_m=distance_m,
        bandwidth_gbps=bandwidth_gbps,
        requested_medium=requested_medium,
        recommended_medium=recommended_medium,
        ethernet_standard=ethernet_standard,
        transceiver=transceiver,
        wavelength_nm=wavelength_nm,
        cable_type=cable_type,
        violation=violation,
        violation_severity=violation_severity,
        violation_message=violation_message,
        attenuation_warning=attenuation_warning,
        explanation=explanation,
        assumptions=assumptions,
        rule_applied=rule_applied,
        is_virtual=False,
    )


def evaluate_all_links(
    links: list[dict],
    raise_on_violation: bool = False,
) -> list[dict]:
    """
    Evaluate physical media for a list of link dictionaries (as used in
    network plan dicts).

    Each link dict must have 'from', 'to', 'distance_m'.  Optionally
    'bandwidth_gbps' and 'requested_medium'.

    Parameters
    ----------
    links : list[dict]
        List of link dicts from a validated network plan.
    raise_on_violation : bool
        Passed through to evaluate_link().  Defaults to False so all links
        are evaluated and violations are recorded structurally.

    Returns
    -------
    list[dict]
        Each element is the original link dict extended with a 'media_decision'
        key holding the MediaDecision for that link.
    """
    results = []
    for link in links:
        distance_m = link.get("distance_m", 0)
        bandwidth_gbps = link.get("bandwidth_gbps")
        requested_medium = link.get("requested_medium")

        try:
            decision = evaluate_link(
                distance_m=distance_m,
                requested_medium=requested_medium,
                bandwidth_gbps=bandwidth_gbps,
                raise_on_violation=raise_on_violation,
            )
        except PhysicalDistanceViolationError as exc:
            raise  # Caller opted in to exceptions

        result = dict(link)
        result["media_decision"] = decision
        results.append(result)

    return results
