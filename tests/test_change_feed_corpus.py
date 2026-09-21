"""The cross-language change-feed corpus from `prism-parity`.

A Human+ surface is SHARED. A person edits the same canvas a PHP application and
a TypeScript or Python agent are editing, and each agent decides from this
answer whether to re-read before writing. If one language reports an
unanswerable feed as "nothing changed", the agent in that language re-reads,
sees current state, decides the surface has drifted from what it intended, and
puts it back OVER THE PERSON'S EDIT — with nothing stale anywhere, so no pin
fires, and no error at any layer.

The fixture is a byte copy vendored into this repo. A runner that reached for a
sibling checkout would work in one directory layout and silently no-op in CI,
which checks out one repo.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from prism_human_plus import ChangeFeed, SurfaceChanges

CORPUS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "human-plus-change-feed.json").read_text(encoding="utf-8")
)


def answer_for(case: dict[str, Any]) -> dict[str, Any]:
    """The same conversion prism-parity's recorder makes."""
    # Parsed HERE, from the corpus's raw JSON text. Carrying the result decoded
    # in the case file would let a round trip through any language normalise the
    # values half these rows exist to test — and Python is the language that
    # tells 1 from 1.0, so it is the one that would notice last.
    result = json.loads(case["input"]["result"])

    return SurfaceChanges.read_from(result, ChangeFeed(case["input"]["feed"])).to_dict()


def test_is_the_whole_suite_not_a_subset_someone_trimmed_to_green() -> None:
    assert len(CORPUS["cases"]) == 23


@pytest.mark.parametrize(
    "case",
    CORPUS["cases"],
    ids=[f"{case['id']} - {case['title']}" for case in CORPUS["cases"]],
)
def test_answers_every_case_as_the_corpus_records(case: dict[str, Any]) -> None:
    produced = json.dumps(answer_for(case), separators=(",", ":"), ensure_ascii=False)

    assert produced == case["rows"]["py"]


def test_agrees_with_the_reference_and_the_typescript_port() -> None:
    for case in CORPUS["cases"]:
        assert [case["rows"]["py"], case["rows"]["ts"]] == [
            case["rows"]["php"],
            case["rows"]["php"],
        ], case["id"]
        assert case["agrees"] is True, case["id"]


def test_still_cannot_tell_an_unanswerable_feed_from_a_quiet_one_by_the_list() -> None:
    # The property the suite exists for, asserted rather than inferred from
    # agreement: hpc-0009 and hpc-0010 differ only in the feed state, and both
    # carry an empty `changes`. A reader that looked at the list would call them
    # the same answer.
    rows = {case["id"]: json.loads(case["rows"]["py"]) for case in CORPUS["cases"]}

    assert rows["hpc-0009"]["changes"] == rows["hpc-0010"]["changes"]
    assert rows["hpc-0009"]["nothing_changed"] is True
    assert rows["hpc-0010"]["nothing_changed"] is False
