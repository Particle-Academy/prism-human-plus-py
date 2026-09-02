"""The cross-language tool-admission corpus from `prism-parity`.

A Human+ surface is SHARED. The same surface is driven by a PHP application and
by this agent, so a tool the reference reserves for the human has to be reserved
here too -- a name refused there and callable here is an agent approving its own
proposals, and nothing errors to say so.

The reservation now agrees in all three languages for every name in the corpus,
including the adversarial ones: G-33 (a trailing newline, which the TypeScript
port used to admit) and G-36 (a trailing SPACE, which ALL THREE used to admit)
are closed by normalising the name. Where this port still differs is the digest
of an integral float (G-35).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from prism_human_plus import ToolDefinition, ToolRefused, TrustPolicy

_CORPUS_PATH = Path(__file__).parent / "fixtures" / "human-plus-tool-admission.json"

with _CORPUS_PATH.open(encoding="utf-8") as handle:
    CORPUS = json.load(handle)


def decide(entry: dict[str, Any]) -> dict[str, Any]:
    # Parsed HERE, from the corpus's raw JSON text -- the corpus explains why it
    # cannot be carried decoded.
    schema = json.loads(entry["tool"]["input_schema_json"])
    tool = ToolDefinition(entry["tool"]["name"], entry["tool"]["description"], schema)
    digest = tool.digest()

    pins = {
        name: (digest if pin == "@digest" else pin)
        for name, pin in (entry["policy"].get("pins") or {}).items()
    }

    mode = entry["policy"]["mode"]
    if mode == "undeclared":
        policy = TrustPolicy.undeclared()
    elif mode == "everyTool":
        policy = TrustPolicy.every_tool(pins)
    else:
        policy = TrustPolicy.allowing(entry["policy"]["tools"], pins)

    declared = True
    message: str | None = None

    try:
        policy.assert_declared()
    except ToolRefused as error:
        declared = False
        message = str(error)

    admitted = True

    try:
        policy.assert_allows(tool)
    except ToolRefused as error:
        admitted = False
        if message is None:
            message = str(error)

    return {
        "digest": digest,
        "declared": declared,
        "allows": policy.allows(tool.name),
        "admitted": admitted,
        "message": message,
    }


def case_of(case_id: str) -> dict[str, Any]:
    return next(entry for entry in CORPUS["cases"] if entry["id"] == case_id)


def test_is_the_whole_suite_not_a_subset_someone_trimmed_to_green() -> None:
    assert len(CORPUS["cases"]) == 32


def test_decides_every_case_the_way_the_corpus_recorded() -> None:
    for entry in CORPUS["cases"]:
        assert decide(entry) == entry["admission"]["py"], entry["id"]


def test_reserves_confirmation_for_the_human_even_under_wildcard_trust() -> None:
    """The property the Lab probes live at /lab/team.

    `every_tool` is the widest trust a caller can express and must still not
    include the one tool an agent must never call -- an agent that can confirm
    approves its own proposals.
    """
    entry = case_of("adm-0005")
    decision = decide(entry)

    assert entry["policy"]["mode"] == "everyTool"
    assert decision["allows"] is False
    assert decision["admitted"] is False


def test_reserves_a_confirm_name_whatever_invisible_character_trails_it() -> None:
    """G-33 and G-36, both CLOSED -- and this is the test that keeps them closed.

    A tool name is chosen by the SURFACE, and ``$`` anchors at the end. A
    trailing newline slipped past the TypeScript port while this one and the
    reference reserved it (G-33); a trailing SPACE slipped past ALL THREE
    (G-36), handing the confirmation tool to the agent under every trust level
    including the wildcard.

    The normalisation strips an EXPLICIT codepoint set, spelled identically in
    all three languages. That detail IS the fix: the built-ins disagree three
    ways -- this language's ``.strip()`` removes every one of these EXCEPT
    U+FEFF, JavaScript's ``.trim()`` removes all of them, and PHP's ``trim()``
    removes none of the Unicode ones -- so reaching for a built-in would have
    closed one hole and opened three new divergences.
    """
    reserved = [
        "adm-0005",
        "adm-0011",
        "adm-0019",
        "adm-0020",
        "adm-0021",
        "adm-0022",
        "adm-0023",
        "adm-0024",
        "adm-0025",
    ]

    for case_id in reserved:
        entry = case_of(case_id)

        assert decide(entry)["allows"] is False, case_id
        assert decide(entry)["admitted"] is False, case_id
        # And the other two agree, which is the half a single-language suite
        # cannot check and the half that was actually broken.
        assert entry["admission"]["php"]["allows"] is False, case_id
        assert entry["admission"]["ts"]["allows"] is False, case_id


def test_still_admits_the_names_that_merely_look_like_a_reserved_verb() -> None:
    """The other half of a reservation, and the half a fix like this can break.

    Normalising only ever reserves MORE names, so these prove it did not
    over-reach: ``confirmation_status`` and ``preconfirm`` stay callable.
    """
    for case_id in ("adm-0009", "adm-0010"):
        entry = case_of(case_id)

        assert decide(entry)["admitted"] is True, case_id
        assert entry["admission"]["php"]["admitted"] is True, case_id
        assert entry["admission"]["ts"]["admitted"] is True, case_id


def test_refuses_a_name_that_is_not_well_formed_in_all_three_languages() -> None:
    """The name rule, and the reason it exists beyond tidiness.

    adm-0026 is the one worth reading. A Cyrillic ``с`` in ``сonfirm`` does NOT
    bypass the reservation -- it genuinely is not ``confirm``, so not reserving
    it is correct -- but a human reading an allowlist cannot tell it from the
    real one. The hole is in the HUMAN's ability to audit the trust config,
    which is the other half of the same trust model. An ASCII-only name rule
    closes it; a cleverer regex over the reserved word never could.
    """
    for case_id in ("adm-0026", "adm-0027", "adm-0028", "adm-0029", "adm-0030"):
        entry = case_of(case_id)

        assert decide(entry)["allows"] is False, case_id
        assert decide(entry)["admitted"] is False, case_id
        assert entry["admission"]["php"]["allows"] is False, case_id
        assert entry["admission"]["ts"]["allows"] is False, case_id


def test_still_admits_the_namespaced_and_hyphenated_names_real_surfaces_use() -> None:
    """The direction a name rule breaks things, and why this one is not stricter.

    Dots, colons and hyphens are how surfaces namespace tools; a rule that
    refused ``vendor.tool`` or ``web-search`` would be unusable and would get
    removed, taking the homoglyph guard with it.
    """
    for case_id in ("adm-0031", "adm-0032"):
        entry = case_of(case_id)

        assert decide(entry)["admitted"] is True, case_id
        assert entry["admission"]["php"]["admitted"] is True, case_id
        assert entry["admission"]["ts"]["admitted"] is True, case_id


def test_digests_a_tool_with_no_schema_the_same_way_typescript_does() -> None:
    """G-34, where the REFERENCE is the odd one out.

    An empty PHP array encodes as ``[]`` and never ``{}``, so a tool declared
    without a schema -- the default, not an edge case -- has a different pin in
    the reference than in either port. A pin computed against a PHP deployment
    therefore fails here, and reads as a tool definition having changed when
    nothing changed at all. G-20's shape, third family.
    """
    entry = case_of("adm-0016")

    assert entry["tool"]["input_schema_json"] == "{}"
    assert decide(entry)["digest"] == entry["admission"]["ts"]["digest"]
    assert decide(entry)["digest"] != entry["admission"]["php"]["digest"]


def test_digests_an_integral_float_differently_from_both_others() -> None:
    """G-35, and this port is the outlier -- which is not the obvious guess.

    ``json.dumps`` renders the float ``1.0`` as ``1.0``; PHP's ``json_encode``
    (serialize_precision -1) and ``JSON.stringify`` both render ``1``. So the
    pair is not "the two languages with a float type" but "everyone except
    Python". The same divergence openai-text-request/trq-0025 records, with a
    PIN as the consequence rather than a request body.

    Pinned in the NEGATIVE.
    """
    entry = case_of("adm-0018")
    digest = decide(entry)["digest"]

    assert digest != entry["admission"]["php"]["digest"]
    assert digest != entry["admission"]["ts"]["digest"]
    assert entry["admission"]["php"]["digest"] == entry["admission"]["ts"]["digest"]


def test_agrees_on_the_pin_the_allowlist_and_every_clean_name() -> None:
    """Everything except the two digest rows still registered (G-34, G-35).

    Asserted as a set so a NEW divergence has somewhere to fail rather than
    disappearing into a row that was already red -- and so that closing either
    one turns this red rather than leaving a stale exemption behind.
    """
    known = {"adm-0016", "adm-0018"}
    unexpected = [
        entry["id"] for entry in CORPUS["cases"] if not entry["agrees"] and entry["id"] not in known
    ]

    assert unexpected == []
