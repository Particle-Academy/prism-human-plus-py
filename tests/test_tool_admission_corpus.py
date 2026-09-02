"""The cross-language tool-admission corpus from `prism-parity`.

A Human+ surface is SHARED. The same surface is driven by a PHP application and
by this agent, so a tool the reference reserves for the human has to be reserved
here too -- a name refused there and callable here is an agent approving its own
proposals, and nothing errors to say so.

This port agrees with the reference on the reservation, INCLUDING the trailing-
newline row the TypeScript port gets wrong (G-33). Where it differs is the
digest of an integral float (G-35).
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
    assert len(CORPUS["cases"]) == 20


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


def test_reserves_a_confirm_name_with_a_trailing_newline_which_typescript_does_not() -> None:
    """G-33, and this port is on the correct side of it.

    Python's ``$`` matches before a final newline, as PCRE's does, so
    ``terminal_confirm\\n`` is reserved here and in the reference. JavaScript's
    ``$`` without the multiline flag matches only at the very end, so the
    TypeScript port hands that tool to the agent.

    A surface chooses its own tool names, which makes the newline attacker-
    controlled. Asserted in the POSITIVE: this is the behaviour to keep.
    """
    entry = case_of("adm-0011")

    assert entry["tool"]["name"].endswith("\n")
    assert decide(entry)["allows"] is False
    assert entry["admission"]["php"]["allows"] is False
    assert entry["admission"]["ts"]["allows"] is True


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


def test_admits_a_confirm_name_with_one_trailing_space_and_so_does_every_other_language() -> None:
    """G-36, and the worst finding in this suite precisely BECAUSE all three agree.

    ``$`` tolerates at most one trailing newline in PCRE and Python and none in
    JavaScript, and nothing normalises the name before matching -- so a surface
    that calls its tool ``terminal_confirm `` gets the confirmation tool handed
    to the agent in every language.

    A cross-language corpus cannot find this by COMPARING languages; there is
    nothing to compare. Asserted in the POSITIVE, describing the hole rather
    than a guarantee, so the day someone closes it this row goes red and forces
    the corpus and the register to move with the fix.

    adm-0020 reaches the same hole with a second newline, which is why a fix
    that only special-cases a single trailing newline -- the shape of G-33 -- is
    visibly not enough.
    """
    for case_id in ("adm-0019", "adm-0020"):
        entry = case_of(case_id)

        assert entry["policy"]["mode"] == "everyTool"
        assert decide(entry)["admitted"] is True, case_id
        assert entry["admission"]["php"]["admitted"] is True, case_id
        assert entry["admission"]["ts"]["admitted"] is True, case_id


def test_agrees_on_the_pin_the_allowlist_and_every_clean_name() -> None:
    """Everything except the three registered rows.

    Asserted as a set so a NEW divergence has somewhere to fail rather than
    disappearing into a row that was already red.
    """
    known = {"adm-0011", "adm-0016", "adm-0018"}
    unexpected = [
        entry["id"] for entry in CORPUS["cases"] if not entry["agrees"] and entry["id"] not in known
    ]

    assert unexpected == []
