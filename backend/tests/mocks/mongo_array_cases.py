"""Array-operator behaviour measured against Percona Server for MongoDB 8.0.17-6.

Every expectation here was recorded from that server, not derived from the documentation. The
same table drives the in-process attrappe and, under ``live_mongo``, a real server, so a case the
two answer differently fails on one side or the other instead of quietly diverging.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.repositories.projects import remove_team_pipeline, replace_team_subset_pipeline, set_owners_pipeline
from scripts.backfill_project_team_ids import drift_filter, provenance_gap_filter

_CONFLICT = 40
_BAD_VALUE = 2
_TYPE_MISMATCH = 14


@dataclass(frozen=True)
class UpdateCase:
    name: str
    seed: dict
    update: dict | list
    expected: dict | None = None
    error_code: int | None = None
    array_filters: list | None = None


@dataclass(frozen=True)
class FindCase:
    name: str
    seeds: list
    query: dict
    expected_ids: list = field(default_factory=list)
    error_code: int | None = None


@dataclass(frozen=True)
class AggCase:
    name: str
    seeds: list
    pipeline: list
    expected: list = field(default_factory=list)


_NESTED = {"a": {"b": {"c": 1}}, "t": [1, 2], "ab": 0}

# Two modifiers may not touch overlapping paths. This is the divergence that matters most for
# array work: a sync that $pulls its own owners and $addToSets the new ones in one update is
# rejected in production, so an attrappe that applies both green-lights an impossible write.
CONFLICT_CASES = [
    UpdateCase(
        "pull and addToSet on one array",
        {"team_ids": ["A", "B"]},
        {"$pull": {"team_ids": {"$in": ["B"]}}, "$addToSet": {"team_ids": {"$each": ["C"]}}},
        error_code=_CONFLICT,
    ),
    UpdateCase(
        "unset and set the same dotted path",
        {"team_sources": {"A": "gitlab"}},
        {"$unset": {"team_sources.A": ""}, "$set": {"team_sources.A": "github"}},
        error_code=_CONFLICT,
    ),
    UpdateCase(
        "unset and set disjoint dotted paths",
        {"team_sources": {"A": "gitlab", "B": "manual"}},
        {"$unset": {"team_sources.A": ""}, "$set": {"team_sources.B": "github"}},
        expected={"team_sources": {"B": "github"}},
    ),
    UpdateCase("set a parent and its child", _NESTED, {"$set": {"a": 1, "a.b": 2}}, error_code=_CONFLICT),
    UpdateCase("set a path and a deeper one", _NESTED, {"$set": {"a.b": 1, "a.b.c": 2}}, error_code=_CONFLICT),
    UpdateCase(
        "set two sibling dotted paths",
        _NESTED,
        {"$set": {"a.b": 1, "a.c": 2}},
        expected={"a": {"b": 1, "c": 2}, "t": [1, 2], "ab": 0},
    ),
    UpdateCase(
        "a shared string prefix is not a path prefix",
        _NESTED,
        {"$set": {"ab": 1, "a": 2}},
        expected={"a": 2, "t": [1, 2], "ab": 1},
    ),
    UpdateCase("set and unset one path", _NESTED, {"$set": {"a.b": 1}, "$unset": {"a.b": ""}}, error_code=_CONFLICT),
    UpdateCase(
        "two array indices are distinct paths",
        _NESTED,
        {"$set": {"a.0": 1, "a.1": 2}},
        expected={"a": {"b": {"c": 1}, "0": 1, "1": 2}, "t": [1, 2], "ab": 0},
    ),
    UpdateCase("an index and its array", _NESTED, {"$set": {"a.0": 1, "a": 2}}, error_code=_CONFLICT),
    UpdateCase(
        "setOnInsert and set one path", _NESTED, {"$setOnInsert": {"a": 1}, "$set": {"a": 2}}, error_code=_CONFLICT
    ),
    UpdateCase(
        "push and addToSet one array", _NESTED, {"$push": {"t": 1}, "$addToSet": {"t": 2}}, error_code=_CONFLICT
    ),
    UpdateCase(
        "pull an array and set an element", _NESTED, {"$pull": {"t": 1}, "$set": {"t.0": 9}}, error_code=_CONFLICT
    ),
    UpdateCase("unset a parent and its child", _NESTED, {"$unset": {"a": "", "a.b": ""}}, error_code=_CONFLICT),
    UpdateCase(
        "disjoint fields across modifiers",
        _NESTED,
        {"$set": {"a": 1}, "$inc": {"b": 1}},
        expected={"a": 1, "t": [1, 2], "ab": 0, "b": 1},
    ),
    # Two array filters address sibling elements, so $[ident] is an ordinary path segment.
    UpdateCase(
        "two array filters on one array",
        {"m": [{"u": 1, "r": "a"}, {"u": 2, "r": "b"}]},
        {"$set": {"m.$[x].r": "z", "m.$[y].r": "q"}},
        expected={"m": [{"u": 1, "r": "z"}, {"u": 2, "r": "q"}]},
        array_filters=[{"x.u": 1}, {"y.u": 2}],
    ),
    UpdateCase(
        "an array filter and its array",
        {"m": [{"u": 1, "r": "a"}]},
        {"$set": {"m.$[x].r": "z", "m": []}},
        error_code=_CONFLICT,
        array_filters=[{"x.u": 1}],
    ),
]

ADD_TO_SET_CASES = [
    UpdateCase(
        "$each appends the new members only",
        {"team_ids": ["A", "B"]},
        {"$addToSet": {"team_ids": {"$each": ["B", "C", "D"]}}},
        expected={"team_ids": ["A", "B", "C", "D"]},
    ),
    UpdateCase(
        "$each dedupes within its own batch",
        {"t": ["A", "B"]},
        {"$addToSet": {"t": {"$each": ["C", "C", "A"]}}},
        expected={"t": ["A", "B", "C"]},
    ),
    UpdateCase(
        "an empty $each changes nothing",
        {"t": ["A", "B"]},
        {"$addToSet": {"t": {"$each": []}}},
        expected={"t": ["A", "B"]},
    ),
    UpdateCase(
        "$each onto a missing field creates the array",
        {"x": 1},
        {"$addToSet": {"t": {"$each": ["a", "b"]}}},
        expected={"x": 1, "t": ["a", "b"]},
    ),
    UpdateCase("$each needs an array", {"t": ["A"]}, {"$addToSet": {"t": {"$each": "C"}}}, error_code=_TYPE_MISMATCH),
    UpdateCase(
        "no modifier may follow $each",
        {"t": ["A"]},
        {"$addToSet": {"t": {"$each": ["C"], "$slice": 1}}},
        error_code=_BAD_VALUE,
    ),
    # Only a document whose *first* key is $each is a batch; anything else is stored verbatim.
    UpdateCase(
        "$each behind another key is a literal",
        {"t": ["A"]},
        {"$addToSet": {"t": {"x": 1, "$each": ["C"]}}},
        expected={"t": ["A", {"x": 1, "$each": ["C"]}]},
    ),
    UpdateCase(
        "a document is stored whole", {"t": ["A"]}, {"$addToSet": {"t": {"x": 1}}}, expected={"t": ["A", {"x": 1}]}
    ),
    UpdateCase(
        "a dotted path descends", {"a": {"b": ["x"]}}, {"$addToSet": {"a.b": "y"}}, expected={"a": {"b": ["x", "y"]}}
    ),
    UpdateCase("an existing member is not re-added", {"t": ["A"]}, {"$addToSet": {"t": "A"}}, expected={"t": ["A"]}),
    UpdateCase(
        "documents dedupe by value", {"t": [{"k": 1}]}, {"$addToSet": {"t": {"k": 1}}}, expected={"t": [{"k": 1}]}
    ),
    # BSON compares documents byte for byte, so a different key order is a different value.
    UpdateCase(
        "key order makes a distinct document",
        {"t": [{"a": 1, "b": 2}]},
        {"$addToSet": {"t": {"b": 2, "a": 1}}},
        expected={"t": [{"a": 1, "b": 2}, {"b": 2, "a": 1}]},
    ),
    UpdateCase("an int and a bool are distinct", {"t": [1]}, {"$addToSet": {"t": True}}, expected={"t": [1, True]}),
    UpdateCase("a non-array target fails", {"t": "s"}, {"$addToSet": {"t": "A"}}, error_code=_BAD_VALUE),
    UpdateCase("a null target fails", {"t": None}, {"$addToSet": {"t": "A"}}, error_code=_BAD_VALUE),
]

PULL_CASES = [
    UpdateCase(
        "$in removes the named members",
        {"team_ids": ["A", "B"]},
        {"$pull": {"team_ids": {"$in": ["B", "Z"]}}},
        expected={"team_ids": ["A"]},
    ),
    UpdateCase("a bare value is an equality", {"t": ["A", "B"]}, {"$pull": {"t": "A"}}, expected={"t": ["B"]}),
    # A missing path is left alone rather than turned into an empty array.
    UpdateCase("a missing field is untouched", {"x": 1}, {"$pull": {"t": "A"}}, expected={"x": 1}),
    UpdateCase("a missing nested field is untouched", {"x": 1}, {"$pull": {"a.b": "A"}}, expected={"x": 1}),
    UpdateCase("a null target fails", {"t": None}, {"$pull": {"t": "A"}}, error_code=_BAD_VALUE),
    UpdateCase("a non-array target fails", {"t": "str"}, {"$pull": {"t": "A"}}, error_code=_BAD_VALUE),
    UpdateCase(
        "a literal array matches a whole element",
        {"t": [["A"], ["B"]]},
        {"$pull": {"t": ["A"]}},
        expected={"t": [["B"]]},
    ),
    UpdateCase("a dotted path descends", {"a": {"b": [1, 2]}}, {"$pull": {"a.b": 1}}, expected={"a": {"b": [2]}}),
    UpdateCase(
        "an operator condition tests each element", {"t": [1, 2, 3]}, {"$pull": {"t": {"$lt": 3}}}, expected={"t": [3]}
    ),
    UpdateCase(
        "a query document tests each sub-document",
        {"m": [{"u": 1, "r": "a"}, {"u": 2, "r": "b"}]},
        {"$pull": {"m": {"u": 1}}},
        expected={"m": [{"u": 2, "r": "b"}]},
    ),
    UpdateCase(
        "a query document never matches a scalar", {"m": [1, 2]}, {"$pull": {"m": {"u": 1}}}, expected={"m": [1, 2]}
    ),
    UpdateCase(
        "an empty condition clears sub-documents", {"t": [{"u": 1}, {"v": 2}]}, {"$pull": {"t": {}}}, expected={"t": []}
    ),
    UpdateCase("an empty condition spares scalars", {"t": [1, 2]}, {"$pull": {"t": {}}}, expected={"t": [1, 2]}),
    # A range operator brackets to its own BSON type, so a document element is out of reach.
    UpdateCase(
        "a range never reaches a sub-document",
        {"m": [{"u": 1}, {"u": 2}]},
        {"$pull": {"m": {"$gt": 4}}},
        expected={"m": [{"u": 1}, {"u": 2}]},
    ),
    UpdateCase(
        "operators and fields may not be mixed",
        {"m": [{"u": 1}]},
        {"$pull": {"m": {"$gt": 4, "u": 1}}},
        error_code=_BAD_VALUE,
    ),
    UpdateCase(
        "$elemMatch reaches into array elements",
        {"m": [[1, 5], [1, 2]]},
        {"$pull": {"m": {"$elemMatch": {"$gt": 4}}}},
        expected={"m": [[1, 2]]},
    ),
    UpdateCase(
        "$elemMatch does not reach sub-documents",
        {"m": [{"u": 1}]},
        {"$pull": {"m": {"$elemMatch": {"u": 1}}}},
        expected={"m": [{"u": 1}]},
    ),
    UpdateCase(
        "$in compares whole sub-documents",
        {"m": [{"u": 1}, {"u": 2}]},
        {"$pull": {"m": {"$in": [{"u": 1}]}}},
        expected={"m": [{"u": 2}]},
    ),
    UpdateCase(
        "a dotted key inside the condition",
        {"m": [{"a": {"b": 1}}, {"a": {"b": 2}}]},
        {"$pull": {"m": {"a.b": 1}}},
        expected={"m": [{"a": {"b": 2}}]},
    ),
]

_ARRAY_DOCS = [
    {"t": ["A", "B"]},
    {"t": ["A"]},
    {"t": []},
    {"t": "A"},
    {"x": 1},
    {"t": [["A", "B"]]},
    {"t": None},
]

# An array field answers an equality both as a whole and element by element.
ARRAY_MATCH_CASES = [
    FindCase("an element equality", _ARRAY_DOCS, {"t": "A"}, [0, 1, 3]),
    FindCase("a whole-array literal", _ARRAY_DOCS, {"t": ["A", "B"]}, [0, 5]),
    FindCase("the empty array", _ARRAY_DOCS, {"t": []}, [2]),
    FindCase("a nested array literal", _ARRAY_DOCS, {"t": [["A", "B"]]}, [5]),
    FindCase("$eq on an element", _ARRAY_DOCS, {"t": {"$eq": "A"}}, [0, 1, 3]),
    FindCase("$eq on the whole array", _ARRAY_DOCS, {"t": {"$eq": ["A", "B"]}}, [0, 5]),
    FindCase("$eq null selects the missing field", _ARRAY_DOCS, {"t": {"$eq": None}}, [4, 6]),
    FindCase("$in over elements", _ARRAY_DOCS, {"t": {"$in": ["B"]}}, [0]),
    FindCase("$in with an array member", _ARRAY_DOCS, {"t": {"$in": [["A", "B"]]}}, [0, 5]),
    FindCase("$nin with an array member", _ARRAY_DOCS, {"t": {"$nin": [["A", "B"]]}}, [1, 2, 3, 4, 6]),
    FindCase("$ne excludes the empty array", _ARRAY_DOCS, {"t": {"$ne": []}}, [0, 1, 3, 4, 5, 6]),
    FindCase("$size counts the elements", _ARRAY_DOCS, {"t": {"$size": 1}}, [1, 5]),
    FindCase("$size zero finds the empty array", _ARRAY_DOCS, {"t": {"$size": 0}}, [2]),
    FindCase("$size needs a number", _ARRAY_DOCS, {"t": {"$size": "x"}}, error_code=_BAD_VALUE),
    FindCase("$size rejects a negative", _ARRAY_DOCS, {"t": {"$size": -1}}, error_code=_BAD_VALUE),
    FindCase("$all also matches a scalar", _ARRAY_DOCS, {"t": {"$all": ["A"]}}, [0, 1, 3]),
    FindCase("an empty $all matches nothing", _ARRAY_DOCS, {"t": {"$all": []}}, []),
    FindCase("$all needs an array", _ARRAY_DOCS, {"t": {"$all": 1}}, error_code=_BAD_VALUE),
    # Dispatch is on the top-level keys alone, so a document without any is a literal to equal.
    FindCase(
        "a sub-document literal is exact",
        [{"a": {"b": 1}}, {"a": {"b": 1, "c": 2}}, {"a": [{"b": 1}]}],
        {"a": {"b": 1}},
        [0, 2],
    ),
    FindCase("an operator nested under a field is a literal", [{"a": {"b": 1}}], {"a": {"b": {"$gt": 0}}}, []),
]

_SCALAR_ARRAY_DOCS = [{"n": [1, 5, 10]}, {"n": [1, 2]}, {"n": [20]}, {"n": "x"}, {"n": 5}, {"n": [{"v": 5}]}]

# $elemMatch applies an operator-only condition to the element itself, so a scalar array matches.
ELEM_MATCH_CASES = [
    FindCase("a range over scalar elements", _SCALAR_ARRAY_DOCS, {"n": {"$elemMatch": {"$gt": 4, "$lt": 15}}}, [0]),
    FindCase("$eq over scalar elements", _SCALAR_ARRAY_DOCS, {"n": {"$elemMatch": {"$eq": 1}}}, [0, 1]),
    FindCase("$in over scalar elements", _SCALAR_ARRAY_DOCS, {"n": {"$elemMatch": {"$in": [20]}}}, [2]),
    FindCase("$ne over scalar elements", _SCALAR_ARRAY_DOCS, {"n": {"$elemMatch": {"$ne": 1}}}, [0, 1, 2, 5]),
    FindCase(
        "$exists finds any non-empty array", _SCALAR_ARRAY_DOCS, {"n": {"$elemMatch": {"$exists": True}}}, [0, 1, 2, 5]
    ),
    FindCase("a field condition needs a sub-document", _SCALAR_ARRAY_DOCS, {"n": {"$elemMatch": {"v": 5}}}, [5]),
    FindCase("a range brackets to its own type", _SCALAR_ARRAY_DOCS, {"n": {"$elemMatch": {"$gt": 4}}}, [0, 2]),
    FindCase(
        "operators and fields may not be mixed",
        _SCALAR_ARRAY_DOCS,
        {"n": {"$elemMatch": {"$gt": 4, "v": 5}}},
        error_code=_BAD_VALUE,
    ),
]

_UNWIND_DOCS = [{"t": ["A", "B"]}, {"t": []}, {"t": None}, {"x": 1}, {"t": "s"}]

UNWIND_CASES = [
    AggCase("the string form", _UNWIND_DOCS, [{"$unwind": "$t"}], [{"t": "A"}, {"t": "B"}, {"t": "s"}]),
    AggCase("the object form", _UNWIND_DOCS, [{"$unwind": {"path": "$t"}}], [{"t": "A"}, {"t": "B"}, {"t": "s"}]),
    # Preserving an empty array drops the field, while a null stays null.
    AggCase(
        "preserveNullAndEmptyArrays",
        _UNWIND_DOCS,
        [{"$unwind": {"path": "$t", "preserveNullAndEmptyArrays": True}}],
        [{"t": "A"}, {"t": "B"}, {}, {"t": None}, {"x": 1}, {"t": "s"}],
    ),
    AggCase(
        "includeArrayIndex",
        _UNWIND_DOCS,
        [{"$unwind": {"path": "$t", "includeArrayIndex": "i"}}],
        [{"t": "A", "i": 0}, {"t": "B", "i": 1}, {"t": "s", "i": None}],
    ),
    AggCase(
        "a nested path preserved",
        [{"a": {"b": ["X", "Y"]}}, {"a": {}}],
        [{"$unwind": {"path": "$a.b", "preserveNullAndEmptyArrays": True}}],
        [{"a": {"b": "X"}}, {"a": {"b": "Y"}}, {"a": {}}],
    ),
]

_TEAM_DOC = {"t": ["A", "B"], "s": {"A": "gitlab"}, "n": 1}

PIPELINE_UPDATE_CASES = [
    UpdateCase(
        "a literal $set stage", _TEAM_DOC, [{"$set": {"t": ["Z"]}}], expected={"t": ["Z"], "s": {"A": "gitlab"}, "n": 1}
    ),
    UpdateCase(
        "$setUnion against the stored array",
        _TEAM_DOC,
        [{"$set": {"t": {"$setUnion": ["$t", ["C"]]}}}],
        expected={"t": ["A", "B", "C"], "s": {"A": "gitlab"}, "n": 1},
    ),
    UpdateCase(
        "a later stage sees the earlier one",
        _TEAM_DOC,
        [{"$set": {"t": {"$setDifference": ["$t", ["A"]]}}}, {"$set": {"k": {"$size": "$t"}}}],
        expected={"t": ["B"], "s": {"A": "gitlab"}, "n": 1, "k": 1},
    ),
    UpdateCase("an $unset stage", _TEAM_DOC, [{"$unset": ["s"]}], expected={"t": ["A", "B"], "n": 1}),
    UpdateCase("an $unset stage naming one field", _TEAM_DOC, [{"$unset": "s"}], expected={"t": ["A", "B"], "n": 1}),
    UpdateCase(
        "an $addFields stage",
        _TEAM_DOC,
        [{"$addFields": {"k": 5}}],
        expected={"t": ["A", "B"], "s": {"A": "gitlab"}, "n": 1, "k": 5},
    ),
    UpdateCase("a $project stage", _TEAM_DOC, [{"$project": {"t": 1}}], expected={"t": ["A", "B"]}),
    UpdateCase(
        "a $replaceRoot stage", _TEAM_DOC, [{"$replaceRoot": {"newRoot": {"only": "$n"}}}], expected={"only": 1}
    ),
    UpdateCase(
        "a $$ROOT reference",
        _TEAM_DOC,
        [{"$set": {"copy": "$$ROOT.n"}}],
        expected={"t": ["A", "B"], "s": {"A": "gitlab"}, "n": 1, "copy": 1},
    ),
    # $setUnion answers in BSON order, unlike $setDifference, which keeps its first operand's.
    UpdateCase(
        "$setUnion reorders the result",
        {"t": ["zeta", "alpha"]},
        [{"$set": {"t": {"$setUnion": ["$t", ["mid"]]}}}],
        expected={"t": ["alpha", "mid", "zeta"]},
    ),
    UpdateCase(
        "$setDifference keeps the first operand's order",
        {"t": ["zeta", "alpha", "mid"]},
        [{"$set": {"t": {"$setDifference": ["$t", ["mid"]]}}}],
        expected={"t": ["zeta", "alpha"]},
    ),
]

# The ownership writes phase 4 performs, and the exact hazard they are guarded against: without
# $ifNull a document missing either field is written team_ids: null, which then matches neither
# the unassigned filter nor an ownership one.
TEAM_OWNERSHIP_CASES = [
    UpdateCase(
        "a provider replaces only the owners it set",
        {
            "team_ids": ["gl-a", "manual-b", "gh-z"],
            "team_sources": {"gl-a": "gitlab", "manual-b": "manual", "gh-z": "github"},
        },
        replace_team_subset_pipeline("gitlab", ["gl-c", "gl-a"]),
        expected={
            "team_ids": ["gh-z", "gl-a", "gl-c", "manual-b"],
            "team_sources": {"manual-b": "manual", "gh-z": "github", "gl-c": "gitlab", "gl-a": "gitlab"},
            "team_id": "gh-z",
            "team_source": "github",
        },
    ),
    UpdateCase(
        "a sync that resolved nothing keeps the manual co-owner",
        {"team_ids": ["manual-b"], "team_sources": {"manual-b": "manual"}},
        replace_team_subset_pipeline("gitlab", []),
        expected={
            "team_ids": ["manual-b"],
            "team_sources": {"manual-b": "manual"},
            "team_id": "manual-b",
            "team_source": "manual",
        },
    ),
    UpdateCase(
        "a sync drops the owner it no longer resolves",
        {"team_ids": ["gl-a", "manual-b"], "team_sources": {"gl-a": "gitlab", "manual-b": "manual"}},
        replace_team_subset_pipeline("gitlab", ["gl-c"]),
        expected={
            "team_ids": ["gl-c", "manual-b"],
            "team_sources": {"manual-b": "manual", "gl-c": "gitlab"},
            "team_id": "gl-c",
            "team_source": "gitlab",
        },
    ),
    UpdateCase(
        "the scalars follow the owner a sync replaced",
        {"team_id": "gl-a", "team_source": "gitlab", "team_ids": ["gl-a"], "team_sources": {"gl-a": "gitlab"}},
        replace_team_subset_pipeline("gitlab", ["gl-b"]),
        expected={
            "team_ids": ["gl-b"],
            "team_sources": {"gl-b": "gitlab"},
            "team_id": "gl-b",
            "team_source": "gitlab",
        },
    ),
    UpdateCase(
        "the scalars stay on an owner the sync did not touch",
        {
            "team_id": "manual-b",
            "team_source": "manual",
            "team_ids": ["manual-b"],
            "team_sources": {"manual-b": "manual"},
        },
        replace_team_subset_pipeline("github", ["gh-a"]),
        expected={
            "team_ids": ["gh-a", "manual-b"],
            "team_sources": {"manual-b": "manual", "gh-a": "github"},
            "team_id": "manual-b",
            "team_source": "manual",
        },
    ),
    UpdateCase(
        "the guard turns absent fields into an empty list",
        {"name": "x"},
        replace_team_subset_pipeline("github", []),
        expected={"name": "x", "team_ids": [], "team_sources": {}, "team_id": None, "team_source": None},
    ),
    UpdateCase(
        "the guard writes the resolved owners onto absent fields",
        {"name": "x"},
        replace_team_subset_pipeline("github", ["gh-1"]),
        expected={
            "name": "x",
            "team_ids": ["gh-1"],
            "team_sources": {"gh-1": "github"},
            "team_id": "gh-1",
            "team_source": "github",
        },
    ),
    UpdateCase(
        "only team_ids is absent",
        {"team_sources": {"m": "manual"}},
        replace_team_subset_pipeline("gitlab", ["g1"]),
        expected={
            "team_ids": ["g1"],
            "team_sources": {"m": "manual", "g1": "gitlab"},
            "team_id": "g1",
            "team_source": "gitlab",
        },
    ),
    UpdateCase(
        "an unguarded pipeline stores null",
        {"name": "x"},
        [{"$set": {"team_ids": {"$setUnion": [{"$setDifference": ["$team_ids", []]}, ["gh-1"]]}}}],
        expected={"name": "x", "team_ids": None},
    ),
    # The picker shows a sync's owners beside the hand-assigned ones, so a retained entry keeping
    # its provenance is what stops any project admin from laundering one into an immortal owner.
    UpdateCase(
        "the whole-set write keeps a retained owner's provenance and stamps the new one",
        {"team_id": "gl-a", "team_source": "gitlab", "team_ids": ["gl-a"], "team_sources": {"gl-a": "gitlab"}},
        set_owners_pipeline(["gl-a", "m1"]),
        expected={
            "team_ids": ["gl-a", "m1"],
            "team_sources": {"gl-a": "gitlab", "m1": "manual"},
            "team_id": "gl-a",
            "team_source": "gitlab",
        },
    ),
    UpdateCase(
        "the whole-set write drops a deselected owner whatever established it",
        {
            "team_id": "gl-a",
            "team_source": "gitlab",
            "team_ids": ["gl-a", "m1"],
            "team_sources": {"gl-a": "gitlab", "m1": "manual"},
        },
        set_owners_pipeline(["m1"]),
        expected={"team_ids": ["m1"], "team_sources": {"m1": "manual"}, "team_id": "m1", "team_source": "manual"},
    ),
    UpdateCase(
        "the whole-set write onto absent fields",
        {"name": "x"},
        set_owners_pipeline(["m1"]),
        expected={
            "name": "x",
            "team_ids": ["m1"],
            "team_sources": {"m1": "manual"},
            "team_id": "m1",
            "team_source": "manual",
        },
    ),
    UpdateCase(
        "a retained owner no provenance names is stamped as hand-assigned",
        {"team_ids": ["legacy"], "team_sources": {}},
        set_owners_pipeline(["legacy"]),
        expected={
            "team_ids": ["legacy"],
            "team_sources": {"legacy": "manual"},
            "team_id": "legacy",
            "team_source": "manual",
        },
    ),
    UpdateCase(
        "picking nothing empties both shapes",
        {"team_id": "gl-a", "team_source": "gitlab", "team_ids": ["gl-a"], "team_sources": {"gl-a": "gitlab"}},
        set_owners_pipeline([]),
        expected={"team_ids": [], "team_sources": {}, "team_id": None, "team_source": None},
    ),
    UpdateCase(
        "a provider leaves an owner no provenance names alone",
        {"team_ids": ["legacy", "gl-a"], "team_sources": {"gl-a": "gitlab"}},
        replace_team_subset_pipeline("gitlab", ["gl-b"]),
        expected={
            "team_ids": ["gl-b", "legacy"],
            "team_sources": {"gl-b": "gitlab"},
            "team_id": "gl-b",
            "team_source": "gitlab",
        },
    ),
    UpdateCase(
        "removing the mirrored owner moves the scalars to a survivor",
        {
            "team_id": "gl-a",
            "team_source": "gitlab",
            "team_ids": ["gl-a", "m1"],
            "team_sources": {"gl-a": "gitlab", "m1": "manual"},
        },
        remove_team_pipeline("gl-a"),
        expected={"team_ids": ["m1"], "team_sources": {"m1": "manual"}, "team_id": "m1", "team_source": "manual"},
    ),
    UpdateCase(
        "removing the last owner empties both shapes",
        {"team_id": "m1", "team_source": "manual", "team_ids": ["m1"], "team_sources": {"m1": "manual"}},
        remove_team_pipeline("m1"),
        expected={"team_ids": [], "team_sources": {}, "team_id": None, "team_source": None},
    ),
    UpdateCase(
        "removing an owner a project never had",
        {"name": "x"},
        remove_team_pipeline("m1"),
        expected={"name": "x", "team_ids": [], "team_sources": {}, "team_id": None, "team_source": None},
    ),
]

DRIFT_DOCS = [
    {"team_id": "T1", "team_source": "manual", "team_ids": ["T1"], "team_sources": {"T1": "manual"}},
    {"team_ids": [], "team_sources": {}},
    {"team_id": None, "team_source": None, "team_ids": [], "team_sources": {}},
    {"team_id": "", "team_source": None, "team_ids": [], "team_sources": {}},
    {"team_id": "T1", "team_ids": ["T1"], "team_sources": {}},
    # A transfer wrote the scalar only: the stored owner and its provenance are both a run behind.
    {
        "team_id": "T_new",
        "team_source": "github",
        "team_ids": ["T_old"],
        "team_sources": {"T_old": "github", "M1": "manual"},
    },
    {"team_id": "T1", "team_source": "manual"},
    {"name": "never-backfilled"},
    {"team_id": "T1", "team_source": "manual", "team_ids": ["T1", "T2"], "team_sources": {"T1": "manual"}},
    {"team_id": "T1", "team_source": "manual", "team_ids": ["T1"], "team_sources": {"T1": "gitlab"}},
    {"team_id": None, "team_source": None, "team_ids": ["T1"], "team_sources": {"T1": "manual"}},
    {"team_id": None, "team_ids": None, "team_sources": {}},
    {"team_id": "T1", "team_source": "manual", "team_ids": ["T1"]},
    # Only the provenance map is missing, and the scalar has no team: the list alone cannot tell
    # this apart from a finished backfill, so the gate has to compare the map raw.
    {"team_ids": [], "team_source": None},
]

# The release gate for dropping the derivation: every document whose stored fields say something
# other than the scalar does, and nothing else. Document 4 is the one an owner-with-no-provenance
# backfill used to leave behind and the gate used to call clean.
TEAM_DRIFT_CASES = [
    FindCase("projects disagreeing with their scalar", DRIFT_DOCS, drift_filter(), [4, 5, 6, 7, 8, 9, 10, 11, 12, 13]),
    FindCase("projects holding an owner no provenance names", DRIFT_DOCS, provenance_gap_filter(), [4, 8, 12]),
]

# An outer element that lacks the inner array contributes nothing rather than a null.
_NESTED_ARRAY_DOCS = [
    {"td": [{"m": [{"u": "a"}, {"u": "b"}]}, {"m": [{"u": "c"}]}]},
    {"td": [{"m": [{"u": "a"}]}, {"name": "no-inner-array"}]},
    {"td": []},
]

_FLATTENED_MEMBER_IDS = {
    "$reduce": {
        "input": {"$ifNull": ["$td", []]},
        "initialValue": [],
        "in": {
            "$setUnion": [
                "$$value",
                {"$map": {"input": {"$ifNull": ["$$this.m", []]}, "as": "e", "in": "$$e.u"}},
            ]
        },
    }
}

ARRAY_EXPRESSION_CASES = [
    AggCase(
        "$objectToArray over a map field",
        [{"s": {"A": "gitlab", "B": "manual"}}, {"x": 1}],
        [{"$project": {"o": {"$objectToArray": {"$ifNull": ["$s", {}]}}}}],
        [{"o": [{"k": "A", "v": "gitlab"}, {"k": "B", "v": "manual"}]}, {"o": []}],
    ),
    AggCase(
        "$arrayToObject from k/v documents",
        [{"p": [{"k": "A", "v": "gitlab"}]}],
        [{"$project": {"o": {"$arrayToObject": "$p"}}}],
        [{"o": {"A": "gitlab"}}],
    ),
    AggCase(
        "$arrayToObject from pairs",
        [{"p": [["A", "g"], ["B", "m"]]}],
        [{"$project": {"o": {"$arrayToObject": "$p"}}}],
        [{"o": {"A": "g", "B": "m"}}],
    ),
    AggCase(
        "$arrayToObject keeps the last duplicate",
        [{"p": [{"k": "A", "v": 1}, {"k": "A", "v": 2}]}],
        [{"$project": {"o": {"$arrayToObject": "$p"}}}],
        [{"o": {"A": 2}}],
    ),
    # A document that lacks the field contributes nothing, while an explicit null is a value.
    AggCase(
        "$push skips a missing field",
        [{"t": 1}, {"x": 9}],
        [{"$group": {"_id": None, "a": {"$push": "$t"}}}],
        [{"_id": None, "a": [1]}],
    ),
    AggCase(
        "$push collects an explicit null",
        [{"t": None}, {"t": 1}],
        [{"$group": {"_id": None, "a": {"$push": "$t"}}}],
        [{"_id": None, "a": [None, 1]}],
    ),
    AggCase(
        "$addToSet skips a missing field",
        [{"t": 1}, {"x": 9}],
        [{"$group": {"_id": None, "a": {"$addToSet": "$t"}}}],
        [{"_id": None, "a": [1]}],
    ),
    # An array literal is an expression: every element is evaluated, and a missing field inside
    # one becomes null rather than dropping out.
    AggCase(
        "an array literal evaluates its elements",
        [{"team_id": "T1"}, {"x": 1}],
        [{"$project": {"a": ["$team_id", 1]}}],
        [{"a": ["T1", 1]}, {"a": [None, 1]}],
    ),
    # Null in, null out for every array operator here — which is how an unguarded pipeline
    # silently stores a null instead of failing.
    AggCase(
        "array operators propagate a missing input",
        [{"x": 1}],
        [
            {
                "$project": {
                    "d": {"$setDifference": ["$nope", []]},
                    "u": {"$setUnion": ["$nope", []]},
                    "m": {"$map": {"input": "$nope", "as": "e", "in": "$$e"}},
                    "f": {"$filter": {"input": "$nope", "as": "e", "cond": True}},
                    "o": {"$objectToArray": "$nope"},
                    "r": {"$reduce": {"input": "$nope", "initialValue": [], "in": "$$value"}},
                }
            }
        ],
        [{"d": None, "u": None, "m": None, "f": None, "o": None, "r": None}],
    ),
    # A path crossing two array levels answers one array per outer element, unflattened — so the
    # owning teams' member ids reach $in as an array of arrays it can never match against.
    AggCase(
        "a field path across two arrays nests",
        _NESTED_ARRAY_DOCS,
        [{"$project": {"p": "$td.m.u"}}],
        [{"p": [["a", "b"], ["c"]]}, {"p": [["a"]]}, {"p": []}],
    ),
    AggCase(
        "$reduce flattens what the path nests",
        _NESTED_ARRAY_DOCS,
        [{"$project": {"p": _FLATTENED_MEMBER_IDS}}],
        [{"p": ["a", "b", "c"]}, {"p": ["a"]}, {"p": []}],
    ),
]


def _without_id(doc: Any) -> Any:
    return {k: v for k, v in doc.items() if k != "_id"}


async def run_update_case(collection, case: UpdateCase) -> dict | None:
    """Seed one document, apply the case's update, and hand back the result minus ``_id``."""
    await collection.delete_many({})
    await collection.insert_one({"_id": 1, **case.seed})
    kwargs = {"array_filters": case.array_filters} if case.array_filters else {}
    await collection.update_one({"_id": 1}, case.update, **kwargs)
    return _without_id(await collection.find_one({"_id": 1}))


async def run_find_case(collection, case: FindCase) -> list:
    await collection.delete_many({})
    for index, seed in enumerate(case.seeds):
        await collection.insert_one({"_id": index, **seed})
    return sorted(doc["_id"] for doc in await collection.find(case.query).to_list(None))


async def run_agg_case(collection, case: AggCase) -> list:
    await collection.delete_many({})
    for index, seed in enumerate(case.seeds):
        await collection.insert_one({"_id": index, **seed})
    rows = await collection.aggregate(case.pipeline).to_list(None)
    # Only a $group sets a meaningful _id; elsewhere it is the seed's key and pins nothing.
    if any("$group" in stage for stage in case.pipeline):
        return rows
    return [_without_id(row) for row in rows]
