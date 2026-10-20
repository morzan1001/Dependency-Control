from __future__ import annotations

import itertools
import re
from typing import NamedTuple

from app.core.constants import LICENSE_ALIASES, LICENSE_URL_PATTERNS, UNKNOWN_LICENSE_PATTERNS

from .constants import LICENSE_DATABASE

_DB_LOWER = {spdx_id.lower(): spdx_id for spdx_id in LICENSE_DATABASE}
_ALIAS_LOWER = {info.name.lower(): spdx_id for spdx_id, info in LICENSE_DATABASE.items()} | {
    alias.lower(): spdx_id for alias, spdx_id in LICENSE_ALIASES.items()
}


def _lookup(lic_id: str) -> str | None:
    if lic_id in LICENSE_ALIASES:
        return LICENSE_ALIASES[lic_id]
    if lic_id in LICENSE_DATABASE:
        return lic_id
    return _ALIAS_LOWER.get(lic_id.lower()) or _DB_LOWER.get(lic_id.lower())


# Free-text licences contain ";" too, so only a Bundle-License parameter marks a header.
BUNDLE_LICENSE_PARAMETER = re.compile(r";\s*(?:link\s*=|description\s*=|see:)", re.IGNORECASE)
_LINK_URL = re.compile(r'link\s*=\s*"?(https?://[^\s";]+)', re.IGNORECASE)
_PARAMETER_URL = re.compile(r'(https?://[^\s";]+)')


def strip_license_parameters(entry: str) -> tuple[str, str | None]:
    """OSGi Bundle-License syntax, which syft copies from jar manifests: "name";link="url";description="..."."""
    name, _, parameters = entry.partition(";")
    # "; see: <url>" names its link without a link= key.
    url = _LINK_URL.search(parameters) or _PARAMETER_URL.search(parameters)
    return name.strip('" '), url.group(1) if url else None


def normalize_license(lic_id: str) -> str:
    lic_id = strip_license_parameters(lic_id)[0]
    known = _lookup(lic_id)
    if known:
        return known
    if lic_id.endswith("+"):
        base = (_lookup(lic_id.rstrip("+")) or "").removesuffix("-only").removesuffix("-or-later")
        return next((spdx_id for spdx_id in (f"{base}-or-later", base) if spdx_id in LICENSE_DATABASE), lic_id)
    return lic_id


def extract_license_from_url(url: str | None) -> str | None:
    if not url:
        return None
    url_lower = url.lower()
    for pattern, spdx_id in LICENSE_URL_PATTERNS.items():
        if re.search(pattern, url_lower):
            return spdx_id
    return None


# Comma-separated parts in the longest known licence title; bounds the re-join window on untrusted input.
_MAX_TITLE_PARTS = 1 + max(
    title.count(",") for title in (*LICENSE_ALIASES, *(info.name for info in LICENSE_DATABASE.values()))
)


# In a Bundle-License header a comma inside quotes belongs to a quoted name or parameter value.
_LIST_PART = re.compile(r'(?:"[^"]*"|[^,])+')


def split_license_list(raw: str) -> list[str]:
    """Licence titles can contain commas, so a plain split would break them."""
    header = BUNDLE_LICENSE_PARAMETER.search(raw)
    parts = [part.strip() for part in (_LIST_PART.findall(raw) if header else raw.split(","))]
    names: list[str] = []
    start = 0
    while start < len(parts):
        window = min(len(parts), start + _MAX_TITLE_PARTS)
        # Parameters close a licence, so a title never runs past the part that carries them.
        window = next(
            (stop + 1 for stop in range(start, window) if BUNDLE_LICENSE_PARAMETER.search(parts[stop])), window
        )
        end = next(
            (
                stop
                for stop in range(window, start + 1, -1)
                if normalize_license(", ".join(parts[start:stop])) in LICENSE_DATABASE
            ),
            start + 1,
        )
        names.append(", ".join(parts[start:end]))
        start = end
    return [name for name in names if name]


_WORD = re.compile(r"[()]|[^\s()]+")
_SYNTAX = frozenset({"AND", "OR", "WITH", "(", ")"})
# Bounds on SBOM-supplied input; past them the expression reads as one unrecognised term beside its certain licences.
_MAX_ALTERNATIVES = 64
_MAX_NESTING = 32

_Groups = list[list[str]]


class _Unparseable(Exception):
    pass


class _Parsed(NamedTuple):
    # None once the expansion passes _MAX_ALTERNATIVES.
    groups: _Groups | None
    # Members every alternative binds, computed without expanding.
    mandatory: dict[str, None]


def _tokens(raw: str) -> list[str]:
    tokens: list[str] = []
    term: tuple[int, int] | None = None
    open_in_term = 0
    for match in _WORD.finditer(raw):
        word = match.group()
        # SPDX never puts '(' right after a licence, so there it belongs to a name like 'License (EDL)'.
        if term and (word == "(" or (word == ")" and open_in_term) or word not in _SYNTAX):
            open_in_term += (word == "(") - (word == ")")
            term = (term[0], match.end())
            continue
        if term:
            tokens.append(raw[term[0] : term[1]])
            term, open_in_term = None, 0
        if word in _SYNTAX:
            tokens.append(word)
        else:
            term = match.span()
    if term:
        tokens.append(raw[term[0] : term[1]])
    return tokens


def _term_ids(term: str) -> list[str]:
    ids = (normalize_license(name) for name in split_license_list(term))
    return list(dict.fromkeys(lic for lic in ids if lic and lic.upper() not in UNKNOWN_LICENSE_PATTERNS))


def _bound(members: list[str]) -> _Parsed:
    return _Parsed([members], dict.fromkeys(members))


def _parse_atom(tokens: list[str], pos: int, depth: int) -> tuple[_Parsed, int]:
    if pos == len(tokens):
        raise _Unparseable
    token = tokens[pos]
    if token == "(":
        if depth == _MAX_NESTING:
            raise _Unparseable
        parsed, pos = _parse_or(tokens, pos + 1, depth + 1)
        if pos == len(tokens) or tokens[pos] != ")":
            raise _Unparseable
        return parsed, pos + 1
    if token in _SYNTAX:
        raise _Unparseable
    if pos + 2 < len(tokens) and tokens[pos + 1] == "WITH" and tokens[pos + 2] not in _SYNTAX:
        return _bound([f"{normalize_license(token)} WITH {tokens[pos + 2]}"]), pos + 3
    return _bound(_term_ids(token)), pos + 1


def _expand_and(parts: list[_Parsed]) -> _Groups | None:
    expanded: list[_Groups] = []
    combinations = 1
    for part in parts:
        if part.groups is None:
            return None
        combinations *= len(part.groups)
        if combinations > _MAX_ALTERNATIVES:
            return None
        expanded.append(part.groups)
    return [list(dict.fromkeys(itertools.chain.from_iterable(combo))) for combo in itertools.product(*expanded)]


def _parse_and(tokens: list[str], pos: int, depth: int) -> tuple[_Parsed, int]:
    part, pos = _parse_atom(tokens, pos, depth)
    parts = [part]
    while pos < len(tokens) and tokens[pos] == "AND":
        part, pos = _parse_atom(tokens, pos + 1, depth)
        parts.append(part)
    mandatory = dict.fromkeys(itertools.chain.from_iterable(part.mandatory for part in parts))
    return _Parsed(_expand_and(parts), mandatory), pos


def _expand_or(alternatives: list[_Parsed]) -> _Groups | None:
    groups: dict[tuple[str, ...], None] = {}
    for alternative in alternatives:
        if alternative.groups is None:
            return None
        groups.update(dict.fromkeys(map(tuple, alternative.groups)))
        if len(groups) > _MAX_ALTERNATIVES:
            return None
    return [list(group) for group in groups if group] or [[]]


def _parse_or(tokens: list[str], pos: int, depth: int) -> tuple[_Parsed, int]:
    alternatives: list[_Parsed] = []
    while True:
        parsed, pos = _parse_and(tokens, pos, depth)
        alternatives.append(parsed)
        if pos == len(tokens) or tokens[pos] != "OR":
            break
        pos += 1
    # A placeholder alternative such as 'MIT OR NOASSERTION' offers no licence to choose.
    offered = [alternative for alternative in alternatives if alternative.groups != [[]]]
    mandatory = dict(offered[0].mandatory) if offered else {}
    for alternative in offered[1:]:
        mandatory = {member: None for member in mandatory if member in alternative.mandatory}
    return _Parsed(_expand_or(alternatives), mandatory), pos


def license_base(member: str) -> str:
    """The licence a parsed 'id WITH exception' member modifies; any other text stays one term."""
    tokens = _tokens(member) if " WITH " in member else []
    if len(tokens) == 3 and tokens[1] == "WITH" and _SYNTAX.isdisjoint((tokens[0], tokens[2])):
        return tokens[0]
    return member


def governing_members(group: list[str]) -> dict[str, str]:
    """Each licence once, mapped to the member whose terms govern; a bare licence outranks its excepted form."""
    governing: dict[str, str] = {}
    for member in group:
        base = license_base(member)
        if base == member or base not in governing:
            governing[base] = member
    return governing


def parse_license_expression(raw: str) -> list[list[str]]:
    """OR-alternatives, each a list of AND-bound normalized ids."""
    tokens = _tokens(raw)
    try:
        parsed, pos = _parse_or(tokens, 0, 0)
        if pos != len(tokens):
            raise _Unparseable
    except _Unparseable:
        parsed = _Parsed(None, {})
    groups = parsed.groups
    if groups is None:
        # The raw term keeps the expression undeterminable; no OR choice becomes an obligation.
        recognised = [member for member in parsed.mandatory if license_base(member) in LICENSE_DATABASE]
        groups = [[*recognised, *_term_ids(raw.strip())]]
    return [group for group in groups if group]


def tokenize_license_string(raw: str) -> list[str]:
    return list(dict.fromkeys(itertools.chain.from_iterable(parse_license_expression(raw))))
